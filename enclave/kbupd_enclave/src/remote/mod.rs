//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

mod peer_manager;
mod sgx_quote;

use crate::prelude::*;

use std::borrow::*;
use std::cell::*;
use std::fmt;
use std::marker::*;
use std::ops::*;
use std::rc::*;
use std::time::*;

use bytes::BufMut;
use chrono::{DateTime, NaiveDateTime, Utc};
use num_traits::ToPrimitive;
use prost::{self, Message};
use serde::Deserialize;
use sgx_ffi::sgx;
use sgx_ffi::util::SecretValue;
use sgxsd_ffi::SHA256Context;
use snow;

use crate::ffi::snow_resolver::*;
use crate::kbupd_send;
use crate::protobufs::kbupd::enclave_message::Inner as EnclaveMessageInner;
use crate::protobufs::kbupd::*;
use crate::protobufs::kbupd_enclave::*;
use crate::util::{self, deserialize_base64};

use self::sgx_quote::*;

//
// public api
//

pub use self::peer_manager::*;

pub const NODE_ID_LEN: usize = 32;

#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum NodeId {
    Valid([u8; NODE_ID_LEN]),
    Invalid(Vec<u8>),
}

#[derive(Clone)]
pub struct NodeParams {
    node_key:  Rc<[u8]>,
    node_id:   NodeId,
    node_type: NodeType,
}

pub struct RemoteSender<M>
where M: prost::Message + 'static
{
    id:     NodeId,
    shared: Rc<RefCell<Shared<M>>>,
}

pub trait RemoteCommon {
    fn id(&self) -> &NodeId;
    fn attestation(&self) -> Option<AttestationParameters>;
}

pub trait RemoteMessageSender: RemoteCommon + fmt::Display {
    type Message: prost::Message;
    fn send(&self, message: Rc<Self::Message>) -> Result<(), ()>;
}

#[must_use]
pub enum RemoteRecvError {
    NeedsAttestation(GetAttestationRequest),
    DecodeError,
    InvalidState,
}

pub enum RemoteAuthorizationType {
    Mutual,
    RemoteOnly,
    SelfOnly,
}

pub trait Remote: RemoteCommon {
    fn connect(&mut self) -> Result<(), ()>;
    fn accept(&mut self, connect_request: PeerConnectRequest) -> Result<(), ()>;
    fn qe_info_reply(&self, sgx_qe_info: &GetQeInfoReply) -> Result<GetQuoteRequest, ()>;
    fn get_quote_reply(&mut self, sgx_quote: GetQuoteReply) -> Result<Option<GetAttestationRequest>, Option<EnclaveGetQuoteReply>>;
    fn attestation_reply(&mut self, ias_report: IasReport) -> Result<Option<AttestationParameters>, ()>;
}

pub struct RemoteState<M, R>
where
    M: prost::Message + 'static,
    R: prost::Message + Default + 'static,
{
    node_params:    Rc<NodeParams>,
    remote_node_id: NodeId,
    remote_type:    NodeType,
    auth_type:      RemoteAuthorizationType,
    shared:         Rc<RefCell<Shared<M>>>,
    _reply:         PhantomData<R>,
}

#[derive(Clone, Default)]
pub struct SharedNoiseBuffers {
    inner: Rc<NoiseBuffers>,
}

//
// RemoteState impls
//

const NOISE_PARAMS: &str = "Noise_KK_25519_AESGCM_SHA256";

const NOISE_CHUNK_MAX_LENGTH: usize = 65535;

struct HandshakeHash {
    hash: [u8; 32],
}

struct Shared<M> {
    session:        SessionState,
    remote_node_id: NodeId,
    noise_buffer:   SharedNoiseBuffers,
    _message:       PhantomData<M>,
}

#[derive(Default)]
struct NoiseBuffers {
    read_buffer:  Cell<Option<SecretValue<Box<NoiseBuffer>>>>,
    write_buffer: RefCell<NoiseBuffer>,
}

struct NoiseBuffer([u8; NOISE_CHUNK_MAX_LENGTH]);

// initiator: Disconnected -> WaitingForAttestation -> Initiated -> Connected -> Authorized
// responder: Disconnected -> Accepted -> Responded -> Authorized
#[allow(clippy::large_enum_variant)]
enum SessionState {
    Disconnected,
    WaitingForAttestation {
        noise: snow::HandshakeState,
    },
    Initiated {
        noise: snow::HandshakeState,
    },
    Connected {
        noise:                snow::TransportState,
        their_handshake_hash: HandshakeHash,
        final_handshake_hash: HandshakeHash,
    },
    Accepted {
        noise:       snow::HandshakeState,
        attestation: Option<AttestationParameters>,
    },
    Responded {
        noise:          snow::TransportState,
        attestation:    Option<AttestationParameters>,
        handshake_hash: HandshakeHash,
    },
    Authorized {
        noise:          snow::TransportState,
        attestation:    Option<AttestationParameters>,
        handshake_hash: HandshakeHash,
    },
}

impl<M, R> RemoteState<M, R>
where
    M: prost::Message + 'static,
    R: prost::Message + Default + 'static,
{
    pub fn new(
        node_params: Rc<NodeParams>,
        remote_node_id: NodeId,
        remote_type: NodeType,
        auth_type: RemoteAuthorizationType,
        noise_buffer: SharedNoiseBuffers,
    ) -> Self
    {
        let shared = Rc::new(RefCell::new(Shared {
            session: SessionState::Disconnected,
            remote_node_id: remote_node_id.clone(),
            noise_buffer,
            _message: Default::default(),
        }));
        Self {
            node_params,
            remote_type,
            remote_node_id,
            auth_type,
            shared,
            _reply: Default::default(),
        }
    }

    pub fn sender(&self) -> RemoteSender<M> {
        RemoteSender {
            id:     self.remote_node_id.clone(),
            shared: Rc::clone(&self.shared),
        }
    }

    fn create_noise_session<Res, BuildFun>(&self, initiator: bool, build_fun: BuildFun) -> Res
    where BuildFun: Fn(snow::Builder<'_>) -> Res {
        let mut prologue_buf = Vec::with_capacity(8);
        if initiator {
            prologue_buf.put_i32_le(self.node_params.node_type.into());
            prologue_buf.put_i32_le(self.remote_type.into());
        } else {
            prologue_buf.put_i32_le(self.remote_type.into());
            prologue_buf.put_i32_le(self.node_params.node_type.into());
        }
        let params = NOISE_PARAMS.parse().unwrap_or_else(|_| unreachable!());
        let builder = snow::Builder::with_resolver(params, Box::new(SnowResolver))
            .prologue(&prologue_buf)
            .local_private_key(&self.node_params.node_key)
            .remote_public_key(&self.remote_node_id);
        build_fun(builder)
    }

    fn initiate_connection(&self) -> Result<snow::HandshakeState, snow::Error> {
        self.create_noise_session(true, |builder| builder.build_initiator())
    }

    fn connection_request(noise: &mut snow::HandshakeState) -> Result<Vec<u8>, snow::Error> {
        let mut msg_buf = vec![0; NOISE_CHUNK_MAX_LENGTH];
        let msg_len = noise.write_message(Default::default(), &mut msg_buf)?;
        msg_buf.truncate(msg_len);
        Ok(msg_buf)
    }

    fn accept_connection(&self, msg_data: &[u8]) -> Result<(snow::HandshakeState, HandshakeHash), snow::Error> {
        let mut noise = self.create_noise_session(false, |builder| builder.build_responder())?;

        let their_handshake_hash = get_handshake_hash(&noise)?;

        noise.read_message(msg_data, &mut [0; 0])?;

        Ok((noise, their_handshake_hash))
    }

    fn connection_response(mut noise: snow::HandshakeState) -> Result<(snow::TransportState, Vec<u8>, HandshakeHash), snow::Error> {
        let mut msg_buf = vec![0; NOISE_CHUNK_MAX_LENGTH];
        let msg_len = noise.write_message(&[0; 0], &mut msg_buf)?;
        msg_buf.truncate(msg_len);

        let handshake_hash = get_handshake_hash(&noise)?;

        let noise = noise.into_transport_mode()?;

        Ok((noise, msg_buf, handshake_hash))
    }

    #[allow(clippy::type_complexity)]
    fn establish_connection(
        mut noise: snow::HandshakeState,
        encrypted_msg_data: &[u8],
    ) -> Result<(snow::TransportState, Vec<u8>, HandshakeHash, HandshakeHash), snow::Error>
    {
        let their_handshake_hash = get_handshake_hash(&noise)?;

        let mut payload_buf = vec![0; encrypted_msg_data.len()];
        let payload_len = noise.read_message(encrypted_msg_data, &mut payload_buf)?;
        payload_buf.truncate(payload_len);

        let final_handshake_hash = get_handshake_hash(&noise)?;

        let noise = noise.into_transport_mode()?;
        Ok((noise, payload_buf, their_handshake_hash, final_handshake_hash))
    }

    pub fn recv(&mut self, msg_data: &[u8]) -> Result<R, RemoteRecvError> {
        let mut shared_ref = self.shared.as_ref().borrow_mut();
        let shared = &mut *shared_ref;
        match &mut shared.session {
            session @ SessionState::Disconnected |
            session @ SessionState::WaitingForAttestation { .. } |
            session @ SessionState::Connected { .. } |
            session @ SessionState::Accepted { .. } => {
                warn!("dropping message from {} in {} state", self.remote_node_id, session);
                Err(RemoteRecvError::InvalidState)
            }
            session @ SessionState::Initiated { .. } => match PeerConnectReply::decode(msg_data) {
                Ok(connect_reply) => {
                    let noise = match std::mem::replace(session, SessionState::Disconnected) {
                        SessionState::Initiated { noise } => noise,
                        _ => unreachable!(),
                    };
                    match Self::establish_connection(noise, &connect_reply.noise_data) {
                        Ok((noise, _payload, their_handshake_hash, final_handshake_hash)) => {
                            *session = SessionState::Connected {
                                noise,
                                their_handshake_hash,
                                final_handshake_hash,
                            };
                            let sgx_quote = connect_reply.sgx_quote;
                            Err(RemoteRecvError::NeedsAttestation(GetAttestationRequest {
                                request_id: self.remote_node_id.to_vec(),
                                sgx_quote,
                            }))
                        }
                        Err(err) => {
                            warn!("error decrypting connect reply from {}: {}", self.remote_node_id, err);
                            Err(RemoteRecvError::DecodeError)
                        }
                    }
                }
                Err(err) => {
                    warn!("error decoding connect reply from {}: {}", self.remote_node_id, err);
                    Err(RemoteRecvError::DecodeError)
                }
            },
            mut session @ SessionState::Responded { .. } | mut session @ SessionState::Authorized { .. } => {
                let noise = match &mut session {
                    SessionState::Responded { noise, .. } => noise,
                    SessionState::Authorized { noise, .. } => noise,
                    _ => static_unreachable!(),
                };
                match read_noise_message(noise, &shared.noise_buffer, msg_data) {
                    Ok(msg_data) => {
                        if let SessionState::Responded { .. } = &session {
                            *session = match std::mem::replace(session, SessionState::Disconnected) {
                                SessionState::Responded {
                                    noise,
                                    attestation,
                                    handshake_hash,
                                } => SessionState::Authorized {
                                    noise,
                                    attestation,
                                    handshake_hash,
                                },
                                _ => unreachable!(),
                            };
                        }

                        match R::decode(&msg_data.get()[..]) {
                            Ok(reply) => Ok(reply),
                            Err(decode_error) => {
                                error!("error decoding message from {}: {}", &self.remote_node_id, decode_error);
                                Err(RemoteRecvError::DecodeError)
                            }
                        }
                    }
                    Err(err) => {
                        error!("error decrypting message from {}: {}", &self.remote_node_id, err);
                        Err(RemoteRecvError::DecodeError)
                    }
                }
            }
        }
    }
}

impl<M, R> RemoteCommon for RemoteState<M, R>
where
    M: prost::Message + 'static,
    R: prost::Message + Default + 'static,
{
    fn id(&self) -> &NodeId {
        &self.remote_node_id
    }

    fn attestation(&self) -> Option<AttestationParameters> {
        self.shared.as_ref().borrow_mut().attestation()
    }
}

impl<M, R> Remote for RemoteState<M, R>
where
    M: prost::Message + 'static,
    R: prost::Message + Default + 'static,
{
    fn connect(&mut self) -> Result<(), ()> {
        if self.node_params.node_id == self.remote_node_id {
            return Err(());
        }

        let mut shared = self.shared.as_ref().borrow_mut();
        let session = match &mut shared.session {
            session @ SessionState::Disconnected |
            session @ SessionState::WaitingForAttestation { .. } |
            session @ SessionState::Initiated { .. } |
            session @ SessionState::Connected { .. } => session,

            SessionState::Accepted { .. } | SessionState::Responded { .. } | SessionState::Authorized { .. } => {
                return Err(());
            }
        };

        match self.initiate_connection() {
            Ok(mut noise) => match self.auth_type {
                RemoteAuthorizationType::Mutual | RemoteAuthorizationType::SelfOnly => {
                    *session = SessionState::WaitingForAttestation { noise };
                }
                RemoteAuthorizationType::RemoteOnly => match Self::connection_request(&mut noise) {
                    Ok(noise_data) => {
                        let connect_req = PeerConnectRequest {
                            node_type: self.node_params.node_type.into(),
                            ias_report: None,
                            noise_data,
                        };
                        let mut connect_req_data = Vec::with_capacity(connect_req.encoded_len());
                        assert!(connect_req.encode(&mut connect_req_data).is_ok());

                        kbupd_send(EnclaveMessage {
                            inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                                node_id:   self.remote_node_id.to_vec(),
                                data:      connect_req_data,
                                syn:       true,
                                debug_msg: None,
                            })),
                        });
                        *session = SessionState::Initiated { noise };
                    }
                    Err(noise_error) => {
                        error!("noise error connecting to {}: {}", &self.remote_node_id, noise_error);
                    }
                },
            },
            Err(noise_error) => {
                error!("error initiating connection with {}: {}", self.remote_node_id, noise_error);
            }
        }
        Ok(())
    }

    fn accept(&mut self, connect_request: PeerConnectRequest) -> Result<(), ()> {
        if self.node_params.node_id == self.remote_node_id {
            return Err(());
        }

        let mut shared = self.shared.as_ref().borrow_mut();
        let session = match &mut shared.session {
            session @ SessionState::Disconnected |
            session @ SessionState::WaitingForAttestation { .. } |
            session @ SessionState::Accepted { .. } |
            session @ SessionState::Responded { .. } => session,

            session @ SessionState::Initiated { .. } => {
                if self.node_params.node_id < self.remote_node_id {
                    session
                } else {
                    warn!("dropping connect request from {} in {} state", self.remote_node_id, session);
                    return Err(());
                }
            }
            session @ SessionState::Connected { .. } | session @ SessionState::Authorized { .. } => {
                warn!("dropping connect request from {} in {} state", self.remote_node_id, session);
                return Err(());
            }
        };

        match self.accept_connection(&connect_request.noise_data) {
            Ok((noise, their_handshake_hash)) => match self.auth_type {
                RemoteAuthorizationType::Mutual | RemoteAuthorizationType::RemoteOnly => {
                    match validate_ias_report(connect_request.ias_report.as_ref(), &their_handshake_hash.hash) {
                        Ok(attestation) => {
                            *session = SessionState::Accepted {
                                noise,
                                attestation: Some(attestation),
                            };
                            Ok(())
                        }
                        Err(attestation_error) => {
                            warn!("attestation error accepting peer {}: {}", self.remote_node_id, attestation_error);
                            Err(())
                        }
                    }
                }
                RemoteAuthorizationType::SelfOnly => {
                    *session = SessionState::Accepted { noise, attestation: None };
                    Ok(())
                }
            },
            Err(noise_error) => {
                error!("decrypt error accepting peer {}: {}", self.remote_node_id, noise_error);
                Err(())
            }
        }
    }

    fn qe_info_reply(&self, reply: &GetQeInfoReply) -> Result<GetQuoteRequest, ()> {
        let shared = self.shared.as_ref().borrow();

        let report_data: [u8; 32] = match &shared.session {
            SessionState::WaitingForAttestation { noise, .. } | SessionState::Accepted { noise, .. } => match get_handshake_hash(noise) {
                Ok(our_handshake_hash) => our_handshake_hash.hash,
                Err(_) => return Err(()),
            },
            SessionState::Authorized { handshake_hash, .. } => handshake_hash.get_hash_for_node(&self.node_params.node_id),
            _ => {
                return Err(());
            }
        };

        #[allow(clippy::cast_possible_truncation)]
        let qe_target_info = sgx::SgxTargetInfo {
            mrenclave:   &reply.mrenclave,
            flags:       reply.flags,
            xfrm:        reply.xfrm,
            misc_select: reply.misc_select,
            config_svn:  reply.config_svn as u16,
            config_id:   &reply.config_id,
        };
        match sgx::create_report(&qe_target_info, &report_data) {
            Ok(sgx_report) => Ok(GetQuoteRequest {
                request_id: self.remote_node_id.to_vec(),
                sgx_report,
            }),
            Err(sgx_error) => {
                warn!("error generating sgx report: {}", sgx_error);
                Err(())
            }
        }
    }

    fn get_quote_reply(&mut self, reply: GetQuoteReply) -> Result<Option<GetAttestationRequest>, Option<EnclaveGetQuoteReply>> {
        let sgx_quote = reply.sgx_quote;
        match &mut self.shared.as_ref().borrow_mut().session {
            SessionState::WaitingForAttestation { .. } => Ok(Some(GetAttestationRequest {
                request_id: self.remote_node_id.to_vec(),
                sgx_quote,
            })),
            session @ SessionState::Accepted { .. } => {
                let (noise, attestation) = match std::mem::replace(session, SessionState::Disconnected) {
                    SessionState::Accepted { noise, attestation } => (noise, attestation),
                    _ => unreachable!(),
                };
                let (noise, noise_data, handshake_hash) = match Self::connection_response(noise) {
                    Ok(result) => result,
                    Err(noise_error) => {
                        error!("error accepting connection request from {}: {}", self.remote_node_id, noise_error);
                        return Err(None);
                    }
                };
                *session = SessionState::Responded {
                    noise,
                    attestation,
                    handshake_hash,
                };

                let msg = PeerConnectReply { sgx_quote, noise_data };
                let mut encoded_msg_data = Vec::with_capacity(msg.encoded_len());
                assert!(msg.encode(&mut encoded_msg_data).is_ok());

                kbupd_send(EnclaveMessage {
                    inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                        node_id:   self.remote_node_id.to_vec(),
                        data:      encoded_msg_data,
                        syn:       false,
                        debug_msg: None,
                    })),
                });

                Ok(None)
            }
            SessionState::Authorized { .. } => Err(Some(EnclaveGetQuoteReply { sgx_quote })),
            _ => Ok(None),
        }
    }

    fn attestation_reply(&mut self, ias_report: IasReport) -> Result<Option<AttestationParameters>, ()> {
        match &mut self.shared.as_ref().borrow_mut().session {
            session @ SessionState::WaitingForAttestation { .. } => {
                let mut noise = match std::mem::replace(session, SessionState::Disconnected) {
                    SessionState::WaitingForAttestation { noise } => noise,
                    _ => unreachable!(),
                };
                match Self::connection_request(&mut noise) {
                    Ok(noise_data) => {
                        let connect_req = PeerConnectRequest {
                            node_type: self.node_params.node_type.into(),
                            ias_report: Some(ias_report),
                            noise_data,
                        };
                        let mut connect_req_data = Vec::with_capacity(connect_req.encoded_len());
                        assert!(connect_req.encode(&mut connect_req_data).is_ok());

                        kbupd_send(EnclaveMessage {
                            inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                                node_id:   self.remote_node_id.to_vec(),
                                data:      connect_req_data,
                                syn:       true,
                                debug_msg: None,
                            })),
                        });
                        *session = SessionState::Initiated { noise };
                        Ok(None)
                    }
                    Err(noise_error) => {
                        error!("noise error connecting to {}: {}", &self.remote_node_id, noise_error);
                        Err(())
                    }
                }
            }
            session @ SessionState::Connected { .. } => {
                let (noise, their_handshake_hash, final_handshake_hash) = match std::mem::replace(session, SessionState::Disconnected) {
                    SessionState::Connected {
                        noise,
                        their_handshake_hash,
                        final_handshake_hash,
                    } => (noise, their_handshake_hash, final_handshake_hash),
                    _ => unreachable!(),
                };
                match validate_ias_report(Some(&ias_report), &their_handshake_hash.hash) {
                    Ok(attestation) => {
                        let handshake_hash = final_handshake_hash;
                        *session = SessionState::Authorized {
                            noise,
                            attestation: Some(attestation),
                            handshake_hash,
                        };
                        Ok(Some(attestation))
                    }
                    Err(attestation_error) => {
                        error!(
                            "error validating attestation report for {}: {}",
                            &self.remote_node_id, attestation_error
                        );
                        Err(())
                    }
                }
            }
            SessionState::Authorized {
                attestation,
                handshake_hash,
                ..
            } => match validate_ias_report(Some(&ias_report), &handshake_hash.get_hash_for_node(&self.remote_node_id)) {
                Ok(new_attestation) => {
                    verbose!("validated attestation report for {}: {}", &self.remote_node_id, &new_attestation);
                    *attestation = Some(new_attestation);
                    Ok(None)
                }
                Err(attestation_error) => {
                    error!(
                        "error validating attestation report for {}: {}",
                        &self.remote_node_id, attestation_error
                    );
                    Err(())
                }
            },
            _ => Err(()),
        }
    }
}

impl<M, R> RemoteMessageSender for RemoteState<M, R>
where
    M: prost::Message + 'static,
    R: prost::Message + Default + 'static,
{
    type Message = M;

    fn send(&self, message: Rc<Self::Message>) -> Result<(), ()> {
        self.shared.as_ref().borrow_mut().send(message)
    }
}

impl<M, R> fmt::Display for RemoteState<M, R>
where
    M: prost::Message + 'static,
    R: prost::Message + Default + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RemoteState")
            .field(&self.remote_node_id)
            .field(&self.remote_type)
            .finish()
    }
}

fn get_handshake_hash(noise: &snow::HandshakeState) -> Result<HandshakeHash, snow::Error> {
    let handshake_hash_slice = noise.get_handshake_hash();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(handshake_hash_slice);
    Ok(HandshakeHash { hash })
}

fn write_noise_message(
    noise: &mut snow::TransportState,
    noise_buffers: &SharedNoiseBuffers,
    payload: &[u8],
) -> Result<Vec<u8>, snow::Error>
{
    let mut noise_buffer_ref = RefCell::borrow_mut(&noise_buffers.inner.write_buffer);
    let chunk_buffer = &mut noise_buffer_ref.0;

    let payload_chunks = payload.chunks(65519);
    let encrypted_msg_buf_len = payload_chunks.len().saturating_mul(NOISE_CHUNK_MAX_LENGTH);
    let mut encrypted_msg_buf = Vec::with_capacity(encrypted_msg_buf_len);
    for payload_chunk in payload_chunks {
        let encrypted_chunk_len = noise.write_message(payload_chunk, chunk_buffer)?;
        let encrypted_chunk_buf = chunk_buffer.get_mut(..encrypted_chunk_len).unwrap_or_else(|| unreachable!());
        encrypted_msg_buf.extend_from_slice(encrypted_chunk_buf);
        noise.rekey_outgoing();
    }
    Ok(encrypted_msg_buf)
}

fn read_noise_message(
    noise: &mut snow::TransportState,
    shared_noise_buffers: &SharedNoiseBuffers,
    encrypted: &[u8],
) -> Result<SecretValue<Vec<u8>>, snow::Error>
{
    let mut noise_buffer = shared_noise_buffers.inner.read_buffer.take().unwrap_or_default();
    match read_noise_message_with_buffer(noise, &mut noise_buffer.get_mut().0, encrypted) {
        Ok(msg_data) => {
            noise_buffer.clear_to(msg_data.get().len());
            shared_noise_buffers.inner.read_buffer.set(Some(noise_buffer));
            Ok(msg_data)
        }
        Err(error) => {
            noise_buffer.clear();
            shared_noise_buffers.inner.read_buffer.set(Some(noise_buffer));
            Err(error)
        }
    }
}

fn read_noise_message_with_buffer(
    noise: &mut snow::TransportState,
    chunk_buffer: &mut [u8; NOISE_CHUNK_MAX_LENGTH],
    encrypted: &[u8],
) -> Result<SecretValue<Vec<u8>>, snow::Error>
{
    let encrypted_chunks = encrypted.chunks(NOISE_CHUNK_MAX_LENGTH);
    let msg_buf_len = encrypted_chunks.len().saturating_mul(65519);
    let mut msg_buf = SecretValue::new(Vec::with_capacity(msg_buf_len));
    for encrypted_chunk in encrypted_chunks {
        let decrypted_chunk_len = noise.read_message(encrypted_chunk, chunk_buffer)?;
        let decrypted_chunk_buf = chunk_buffer.get_mut(..decrypted_chunk_len).unwrap_or_else(|| unreachable!());
        msg_buf.get_mut().extend_from_slice(decrypted_chunk_buf);
        noise.rekey_incoming();
    }
    Ok(msg_buf)
}

impl fmt::Display for SessionState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Disconnected => write!(fmt, "Disconnected"),
            SessionState::WaitingForAttestation { .. } => write!(fmt, "WaitingForAttestation"),
            SessionState::Initiated { .. } => write!(fmt, "Initiated"),
            SessionState::Connected { .. } => write!(fmt, "Connected"),
            SessionState::Accepted { .. } => write!(fmt, "Accepted"),
            SessionState::Responded { .. } => write!(fmt, "Responded"),
            SessionState::Authorized { .. } => write!(fmt, "Authorized"),
        }
    }
}

static IAS_TRUST_ANCHORS: &webpki::TLSServerTrustAnchors<'_> = &webpki::TLSServerTrustAnchors(&[webpki::TrustAnchor {
    subject:          &[
        49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11,
        83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114,
        112, 111, 114, 97, 116, 105, 111, 110, 49, 48, 48, 46, 6, 3, 85, 4, 3, 12, 39, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32, 65, 116,
        116, 101, 115, 116, 97, 116, 105, 111, 110, 32, 82, 101, 112, 111, 114, 116, 32, 83, 105, 103, 110, 105, 110, 103, 32, 67, 65,
    ],
    spki:             &[
        48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 143, 0, 48, 130, 1, 138, 2, 130, 1, 129, 0, 159, 60, 100, 126,
        181, 119, 60, 187, 81, 45, 39, 50, 192, 215, 65, 94, 187, 85, 160, 250, 158, 222, 46, 100, 145, 153, 230, 130, 29, 185, 16, 213,
        49, 119, 55, 9, 119, 70, 106, 106, 94, 71, 134, 204, 210, 221, 235, 212, 20, 157, 106, 47, 99, 37, 82, 157, 209, 12, 201, 135, 55,
        176, 119, 156, 26, 7, 226, 156, 71, 161, 174, 0, 73, 72, 71, 108, 72, 159, 69, 165, 161, 93, 122, 200, 236, 198, 172, 198, 69, 173,
        180, 61, 135, 103, 157, 245, 156, 9, 59, 197, 162, 233, 105, 108, 84, 120, 84, 27, 151, 158, 117, 75, 87, 57, 20, 190, 85, 211, 47,
        244, 192, 157, 223, 39, 33, 153, 52, 205, 153, 5, 39, 179, 249, 46, 215, 143, 191, 41, 36, 106, 190, 203, 113, 36, 14, 243, 156,
        45, 113, 7, 180, 71, 84, 90, 127, 251, 16, 235, 6, 10, 104, 169, 133, 128, 33, 158, 54, 145, 9, 82, 104, 56, 146, 214, 165, 226,
        168, 8, 3, 25, 62, 64, 117, 49, 64, 78, 54, 179, 21, 98, 55, 153, 170, 130, 80, 116, 64, 151, 84, 162, 223, 232, 245, 175, 213,
        254, 99, 30, 31, 194, 175, 56, 8, 144, 111, 40, 167, 144, 217, 221, 159, 224, 96, 147, 155, 18, 87, 144, 197, 128, 93, 3, 125, 245,
        106, 153, 83, 27, 150, 222, 105, 222, 51, 237, 34, 108, 193, 32, 125, 16, 66, 181, 201, 171, 127, 64, 79, 199, 17, 192, 254, 71,
        105, 251, 149, 120, 177, 220, 14, 196, 105, 234, 26, 37, 224, 255, 153, 20, 136, 110, 242, 105, 155, 35, 91, 180, 132, 125, 214,
        255, 64, 182, 6, 230, 23, 7, 147, 194, 251, 152, 179, 20, 88, 127, 156, 253, 37, 115, 98, 223, 234, 177, 11, 59, 210, 217, 118,
        115, 161, 164, 189, 68, 196, 83, 170, 244, 127, 193, 242, 211, 208, 243, 132, 247, 74, 6, 248, 156, 8, 159, 13, 166, 205, 183, 252,
        238, 232, 201, 130, 26, 142, 84, 242, 92, 4, 22, 209, 140, 70, 131, 154, 95, 128, 18, 251, 221, 61, 199, 77, 37, 98, 121, 173, 194,
        192, 213, 90, 255, 111, 6, 34, 66, 93, 27, 2, 3, 1, 0, 1,
    ],
    name_constraints: None,
}]);
static IAS_CHAIN_ALGOS: &'static [&webpki::SignatureAlgorithm] = &[
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
];

#[derive(Debug)]
enum AttestationVerificationError {
    NoAttestationReport,
    InvalidJson(serde_json::Error),
    InvalidCertificate(webpki::Error),
    InvalidSignature(webpki::Error),
    WrongVersion(u64),
    InvalidTimestamp(String),
    StaleRevocationList,
    InvalidQuote(SgxQuoteDecodeError),
    #[cfg(not(feature = "insecure"))]
    IsDebugQuote,
    InvalidQuoteReportData,
    InvalidMrenclave([u8; 32]),
    CreateReportError(u32),
    AttestationError(String),
}

fn parse_ias_timestamp(timestamp: &str) -> Result<u64, AttestationVerificationError> {
    (NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.f").ok())
        .map(|naive_datetime: NaiveDateTime| DateTime::from_utc(naive_datetime, Utc))
        .and_then(|utc_datetime: DateTime<Utc>| utc_datetime.timestamp().to_u64())
        .ok_or_else(|| AttestationVerificationError::InvalidTimestamp(timestamp.to_owned()))
}

fn validate_ias_report(
    maybe_ias_report: Option<&IasReport>,
    expected_report_data: &[u8],
) -> Result<AttestationParameters, AttestationVerificationError>
{
    #[cfg(feature = "insecure")]
    {
        match maybe_ias_report.as_ref() {
            Some(ias_report) if ias_report.body.is_empty() => {
                return Ok(AttestationParameters { unix_timestamp_seconds: 0 });
            }
            _ => (),
        }
    }

    let ias_report = match maybe_ias_report {
        Some(ias_report) => ias_report,
        None => {
            return Err(AttestationVerificationError::NoAttestationReport);
        }
    };

    let body: IasReportBody = serde_json::from_slice(&ias_report.body[..]).map_err(AttestationVerificationError::InvalidJson)?;

    if body.version != 4 {
        return Err(AttestationVerificationError::WrongVersion(body.version));
    }

    match body.isvEnclaveQuoteStatus.as_str() {
        "OK" => {}
        "0x7F770659065E" | "0x7FAF85B9CF32" | "0x7F5CC0CFB6A8" | "0x7F1D2C8A7222" | "0x7FA49763C830" | "0x7FBE1932137F" | "0x7FF087B91FF3" | "0x7F89162488E5" | "0x7F117318762E" | "0x7FB959083D4A" | "0x7F505D581C2D" | "0x7FE866175DE3" | "0x7F54304A05CC" | "0x7FA04D59F9F2" | "0x7F984989EBB6" | "0x7F7C625E9F38" | "0x7FCD71976B76" | "0x7F0C61FFD433" | "0x7FCB81EE0972" | "0x7F3E762808DE" | "0x7FD42B5B811F" | "0x7F6959FF626D" | "0x7F91254509A9" | "0x7F70915951EC" | "0x7F7B23B825B3" | "0x7F20B0B355E6" | "0x7FE614EA46C9" | "0x7F84940BD38A" | "0x7F6B62283711" | "0x7FD7D7A416DC" | "0x7F6593A4F90E" | "0x7F60C361ED83" | "0x7F50FC8BFDC0" | "0x7F6BD0005FE3" | "0x7F13F8A610D7" | "0x7F635A7F177B" | "0x7F4E2A09DBA0" | "0x7F3F0178B262" | "0x7FECBC48AAC5" | "0x7F076464B301" | "0x7F278019143A" | "0x7FB0160C1637" | "0x7F51E62E72BC" | "0x7F44D1196996" | "0x7FF620FBD0D8" | "0x7FF7D5C2D192" | "0x7F784489DC69" | "0x7FAFEE1ACD9C" | "0x7FA4A80C1EA0" | "0x7F645FC27DF8" | "0x7FDB6D1FF2A5" | "0x7F0AD6040690" | "0x7F5DE6BC4706" | "0x7FCE663A555C" | "0x7F2FB09DC06B" | "0x7F314414BA70" | "0x7F7BB99F7EF6" | "0x7FA88AF5106A" | "0x7FD9E4E3E548" | "0x7FB6BADEB04D" | "0x7F5DF472853B" | "0x7F5B8E852E78" | "0x7F0172DCCA67" | "0x7FF3DDBA95CF" | "0x7F1BCE870BB3" | "0x7F459CE4D8A9" | "0x7F088166F0D8" | "0x7F2B2C25709F" | "0x7F34762A1056" | "0x7F9233005D79" | "0x7F7B7522BF62" | "0x7F21CD4EEF56" | "0x7F27213F8AC9" | "0x7FFD33B0AF21" | "0x7FAD18C97CE1" | "0x7F151DE556BE" | "0x7FB2A6862091" | "0x7F1777A5E591" | "0x7FE50CE05B5A" | "0x7FE54B81333D" | "0x7F8151C4C45D" | "0x7FBF8BF2D21A" | "0x7F1BB0FA0C24" | "0x7F5848759B02" | "0x7FBE196B4B52" | "0x7FD4D4BC3F21" | "0x7FDF39522C37" | "0x7F8CB6FC806B" | "0x7FB19134A7C2" | "0x7FB39B3D0156" | "0x7F9E0745AC64" | "0x7F8AAB4DBEC2" | "0x7FC76E65E16B" | "0x7F9A56B04D79" | "0x7FBEE18823F7" | "0x7FAAD91B5434" | "0x7F5FFB13A730" | "0x7FA01ADC65DE" | "0x7FF9EAA150E6" | "0x7F2D9D35C27C" | "0x7FC3B380C885" | "0x7F924F099FD5" | "0x7FDDB795E908" | "0x7FA990B2FB27" | "0x7F477BEF1AC6" | "0x7F728941B4A5" | "0x7FB0BC92BC5C" | "0x7F17D2FAE721" | "0x7FA60A4D0501" | "0x7FD0D19A9F46" | "0x7F6D037A2EBE" | "0x7F7978EF8E12" | "0x7FDDAF596B71" | "0x7FE92C373633" | "0x7F0413EA42CB" | "0x7FE5C7CEF9C9" | "0x7FD2E6A9AD16" | "0x7F8F5E574157" | "0x7FABADAC3604" | "0x7F388125A654" | "0x7F3AD32391BD" | "0x7FD36D8D590A" | "0x7F67CC12CFF5" | "0x7F34AB08588A" | "0x7F6E5C9BF96A" | "0x7F6E14B575F1" | "0x7F453550280F" | "0x7FD4BA69DAE0" | "0x7F22A9350D7A" | "0x7F76D2AAD62B" | "0x7F49D291CCDE" | "0x7FB07AFE70E5" | "0x7FFA3041189E" | "0x7F34449F113C" | "0x7F15B9D04FC1" | "0x7F1F4BD88A9F" | "0x7F5FBDFF294F" | "0x7FB5E1EEB35F" | "0x7F727390E759" | "0x7F100543E51E" | "0x7F573A52DD75" | "0x7FCEAD582EA1" | "0x7F6C007B8455" | "0x7FC04932F23C" | "0x7F6A8EC97D1C" | "0x7F9839AA2F92" | "0x7F3A85BDAF96" | "0x7FA4CFB02FA3" | "0x7F01CE7305EF" | "0x7F1674D065F9" | "0x7FB1ED8D5B33" | "0x7F5E3F79DD64" | "0x7F2EEEE7C112" | "0x7F3C03507E52" | "0x7F1F782C82B6" | "0x7F8F5DB8A24E" | "0x7F2497AB9826" | "0x7FBD521BCF10" | "0x7F1C11444DF4" | "0x7FB2FA1E49F2" | "0x7FABE068871F" | "0x7F6ED2A54003" | "0x7FEC2A1F68D9" | "0x7FABDA4B59F8" | "0x7FEF556535C9" | "0x7F5225109071" | "0x7FC6A054AE2E" | "0x7F4E97271310" | "0x7FFBD05E85EF" | "0x7F6BC62DBD3B" | "0x7F49EE61670D" | "0x7F84EB9735AC" | "0x7F64E209AF93" | "0x7F16BA882000" | "0x7FCCC940565D" | "0x7F31CBA4283D" | "0x7F1DF127DB01" | "0x7F09845CA7D1" | "0x7F02B6EEC7A4" | "0x7FF4847D5667" | "0x7F2676B714E5" | "0x7FFB3A4E40AF" | "0x7FBF145FCC39" | "0x7F60C698DFE4" | "0x7F30C62C23EE" | "0x7F1416CC5AD1" | "0x7FED6F7710A2" | "0x7F7820C1BD6C" | "0x7F068E0F8760" | "0x7F5C1628AAD8" | "0x7F63D826A4DF" | "0x7FFB7D46FEC4" | "0x7F5A579A92DD" | "0x7F6ADE083844" | "0x7F664752BD09" | "0x7FA930AED1B2" | "0x7F4AD6842F3C" | "0x7F34D37DCED5" | "0x7FA7CFAB60B1" | "0x7FD5C921DA7C" | "0x7F1E9F1827FD" | "0x7F429B5B99A3" | "0x7FC8A68686ED" | "0x7F10DE3C46DD" | "0x7F407E305B60" | "0x7F02C14F51FA" | "0x7F09FF16D85F" | "0x7FE671275017" | "0x7F833E2825FB" | "0x7F3AE5F7B0B7" | "0x7F09534E8711" | "0x7F02450EAE72" | "0x7F4980448DD9" | "0x7F2383BFF316" | "0x7FFF7B377DA6" | "0x7F5945A27EA2" | "0x7F82AF9C0A6D" | "0x7F8CAEBC8112" | "0x7FF55A64FA20" | "0x7F2D144F1919" | "0x7F09C357CFBE" | "0x7F52331558FF" | "0x7F5454039554" | "0x7FAFAD101EB3" | "0x7FAA8E844C2E" | "0x7F719D7DDB0B" | "0x7FB07CF905C8" | "0x7FDE5D9BAFB4" | "0x7F4F03687E34" | "0x7F94FE817267" | "0x7F3B5A1A2783" | "0x7F655E34C048" | "0x7F5A346057C5" | "0x7FB774D9A389" | "0x7F3CD0C18ABE" | "0x7FDBCE675DF1" | "0x7FD4CD6EC451" | "0x7FCE2C905AFC" | "0x7F720A76C8E7" | "0x7F80ADEE1B73" | "0x7F9A9F1BAC56" | "0x7F14A278CECE" | "0x7F1F1D805378" | "0x7FA967E6EC14" | "0x7FE1CF37D0F7" | "0x7F42EF10D90F" | "0x7FD1D85BD5DB" | "0x7F8D32A46EE0" | "0x7F8138A146A8" | "0x7F7676D5ED63" | "0x7F7A0DFD2263" | "0x7FAB866A6712" | "0x7FA031DCEE00" | "0x7F5FC29EAECA" | "0x7FF159B93666" | "0x7F938D3AF3BF" | "0x7F77C0E84828" | "0x7F9C236DC0BD" | "0x7F34CC0801BA" | "0x7FCBC246091C" | "0x7F177CEEC46A" | "0x7F61C1E7B239" | "0x7F67501425C2" | "0x7FC5683489B2" | "0x7F909CFC751A" | "0x7F6DA524F0C0" | "0x7F3033A5E948" | "0x7F536CEDA6BF" | "0x7F41A7960094" | "0x7F911650CCE8" | "0x7F97A7577441" | "0x7FBA283E7914" | "0x7F1E4D72B695" | "0x7FC9E428B2DF" | "0x7FB49251D06A" | "0x7F8BB6552008" | "0x7FFA79F8B2AF" | "0x7F8AA576FFCD" | "0x7FE8A0A1E57F" | "0x7F4B9669BC23" | "0x7FDA69CD35C9" | "0x7FD60AEE06BE" | "0x7F4A6E9D2784" | "0x7F89CDDE3890" | "0x7FBFF68C789F" | "0x7F381A4F56B6" | "0x7F575EEC5DBE" | "0x7FDBBD91CC57" | "0x7F281B6BA226" | "0x7F771BB82BF7" | "0x7F7123DCF1E9" | "0x7FD617F883CF" | "0x7F0E23D0902B" | "0x7FC0326153EA" | "0x7FB9F5E75EC7" | "0x7F16EA44E6A3" | "0x7F0380B1CA87" | "0x7F7BAF10A5EB" | "0x7F7684C4CC6C" | "0x7FF9249FC778" | "0x7F5BF524CEA1" | "0x7F45425799AF" | "0x7F8B86F125DB" | "0x7FC0010CA457" | "0x7F3576B4D12C" | "0x7F053D4CD041" | "0x7FF7F7E6EA71" | "0x7FFD5A7A4F1C" | "0x7F1AF1101EAC" | "0x7FB5A02B5DCB" | "0x7FA471F839D6" | "0x7F8179BE728B" | "0x7FC694BB25BB" | "0x7F2A350EF64D" | "0x7F18DEC999C6" | "0x7F5422C33F6D" | "0x7F8788CA3490" | "0x7F059DE31233" | "0x7F2009BA5192" | "0x7F766F358499" | "0x7F161F90781E" | "0x7F5632C65445" | "0x7F0E38E3DB7F" | "0x7F90264A4BC6" | "0x7F6E6197064F" | "0x7F692F8F4143" | "0x7F7A6FAE5D71" | "0x7F8F1CE11A44" | "0x7FA6B440ED97" | "0x7F499C00ADA3" | "0x7FB41283C5A2" | "0x7F676CCAE15D" | "0x7F258A8692BF" | "0x7F6F08508952" | "0x7F0D2D61D35F" | "0x7F272203D320" | "0x7F6CC9303FBC" | "0x7F2918662B84" | "0x7F9991EFEF14" | "0x7F33A05DFB3F" | "0x7FAF31615CEC" | "0x7F5192003960" | "0x7F8C7B71999F" | "0x7F3ECB73B05D" | "0x7F80E1F237C8" | "0x7F54105DF43A" | "0x7F1C3E153225" | "0x7F1678B9196D" | "0x7F55EE464CC6" | "0x7FFD9DF711B0" | "0x7F6D179BB681" | "0x7F00C0358448" | "0x7FD07E9F895E" | "0x7FB61BDD291C" | "0x7FAAC1D8DCFB" | "0x7F8EE0FE4BFF" | "0x7F6B3BE5EBB0" | "0x7F295E4EBE23" | "0x7FE62CC0E918" | "0x7FC3091FBA52" | "0x7FFA835535D0" | "0x7FC2BE87C1D8" | "0x7F672631FF4F" | "0x7F7F12E40649" | "0x7FBB57508967" | "0x7F08A20CBE4F" | "0x7FF98E576418" | "0x7F7C77861930" | "0x7F3806246E1E" | "0x7FD9DED31649" | "0x7F79DC83839B" | "0x7FFD1F47C414" | "0x7FE9CD334B6E" | "0x7FB0752A428D" | "0x7FC850D2109C" | "0x7FBA69DFE93F" | "0x7FB15C5D57D2" | "0x7F447795D8B7" | "0x7FEBFA25BC06" | "0x7F1E938F4959" | "0x7F45A157A872" | "0x7FC4AFE9EC8E" | "0x7F9E8BEFC602" | "0x7FB1222D4FB3" | "0x7FC284990925" | "0x7F915101EF22" | "0x7F17B02C6A4A" | "0x7FD10B248E38" | "0x7FBC14C55D72" | "0x7F205598568E" | "0x7FA8083DC704" | "0x7FC38A676C8B" | "0x7F4AAB169B5D" | "0x7F9B9D78EDCC" | "0x7FB63DF25689" | "0x7FE5439CFC45" | "0x7FC2D7468EFD" | "0x7F5E3B6DDCF1" | "0x7F0779F3BBCD" | "0x7FD8E918B313" | "0x7F5A60B672FA" | "0x7FB2953AABF6" | "0x7F966C66BE8D" | "0x7FB9F9B18CCF" | "0x7FB61340230B" | "0x7F0EDC4C53A1" | "0x7FA664E349C7" | "0x7F45DA001CDA" | "0x7FE267064A45" | "0x7F925C5755E7" | "0x7F5B8E811B1B" | "0x7FF775B46319" | "0x7F11C4EC2B01" | "0x7FFFC14D7E37" | "0x7FB46CE3262D" | "0x7F1989918A63" | "0x7F54B427CFA3" | "0x7F9C7EE9639C" | "0x7F780B08F99F" | "0x7F48FEA8196A" | "0x7F8F3FA76480" | "0x7FB67980B1C1" | "0x7F6292C23099" | "0x7FF43F9E6E90" | "0x7F2DDC9BA24F" | "0x7F48290F2370" | "0x7F5E7E4A63BD" | "0x7F7A883FB7FF" | "0x7F4AEA30F2CB" | "0x7F98B0F68A3C" | "0x7F53F50597DC" | "0x7F3AEA4BFF2E" | "0x7F40E945AF38" | "0x7FB25B572B28" | "0x7F0BCD9EFC74" | "0x7FA651D47208" | "0x7F13D863FFFF" | "0x7F2FC94D7A59" | "0x7F83C6B3872D" | "0x7FE467FFE269" | "0x7F8CD3988F29" | "0x7F6716CE44FA" | "0x7F32D350B84B" | "0x7FEDE141D40A" | "0x7F65CF648553" | "0x7F887072DBE4" | "0x7F88F57E16BD" | "0x7F047C523FB9" | "0x7F4CCFF38C79" | "0x7FE2F80D15A3" | "0x7FB8911E4ADF" | "0x7F9D3E81DBF3" | "0x7FA32F1B9491" | "0x7F68E6E91B6C" | "0x7FD16B4227C2" | "0x7FEB19925FD6" | "0x7F9BAE90343A" | "0x7FF84A9DDA1C" | "0x7F2B5B5E681E" | "0x7FF136615EB7" | "0x7F6AD0AE9D91" | "0x7FAC7026B400" | "0x7F778FAD9403" | "0x7FECC46CBEE5" | "0x7F9CC23358CE" | "0x7FF5865D462A" | "0x7F4C46520532" | "0x7F645F4C67AE" | "0x7F179C07F0CC" | "0x7F37B7C142B8" | "0x7F27C087FA7B" | "0x7F5F6BC67150" | "0x7F8F655808AC" | "0x7FB7D1CF9248" | "0x7F0B805E214B" | "0x7F8FE04D236E" | "0x7FEDDAD19EDB" | "0x7F9FBB8E478F" | "0x7FAEBDD533B9" | "0x7F2C5F7EB4DF" | "0x7F5767D792E2" | "0x7FB6678C1C08" | "0x7F705897FEC3" | "0x7F610A642D44" | "0x7F5B033ABA34" | "0x7FFDF5E5AC34" | "0x7F55F60BCC4E" | "0x7FFCB9E78599" | "0x7F829DD7D111" | "0x7F01AD1164A3" | "0x7FB9E33CF768" | "0x7FEE7944DC33" | "0x7FA7E55789E9" | "0x7F6E15C38CF8" | "0x7F51381459C1" | "0x7F81D700E629" | "0x7F02B29D8D5A" | "0x7F6341806004" | "0x7F7757588D99" | "0x7F4E3B2AB758" | "0x7FA03AD81345" | "0x7FBB6E9EA0EF" | "0x7F6CA72F4A35" | "0x7FF30906F664" | "0x7FB72E71D993" | "0x7F63CA9400B1" | "0x7F046E11F178" | "0x7F98D51659C7" | "0x7F2E64E28D23" | "0x7FCD35546C28" | "0x7F1CBD54A926" | "0x7F04DC2076AD" | "0x7F6F02A4036F" | "0x7FD20E1EE64F" | "0x7F5EEF6D166B" | "0x7F47DC166616" | "0x7F3509719F7E" | "0x7FD37E042120" | "0x7F2DDAD41A51" | "0x7FEDD41877D8" | "0x7F16CA4E2037" | "0x7F47A3EE2847" | "0x7F993C391346" | "0x7F2A03C7BF9D" | "0x7FFDF50BDCE0" | "0x7FEE006544EF" | "0x7F2460805424" | "0x7FC380FC007C" | "0x7F3F91423B1D" | "0x7F7EDE5BE875" | "0x7F25264B02EA" | "0x7F625F2CDE93" | "0x7F2185F9C03E" | "0x7F7FDFD3BE2A" | "0x7FB768CE38E1" | "0x7FA7A0E9DB0D" | "0x7FB98DE9F880" | "0x7F126C4C338C" | "0x7FDB93E37C5E" | "0x7F05599C7027" | "0x7F62FA2584DF" | "0x7F80529368F0" | "0x7F5726101800" | "0x7F951EBFE8DC" | "0x7F2A360AA949" | "0x7F99117175CF" | "0x7F2511982C39" | "0x7F15D43A2751" | "0x7F53A62EB449" | "0x7F4A20713C0C" | "0x7F9A22201D43" | "0x7F50DEC9E416" | "0x7FD9B067D132" | "0x7FC2E1102CBE" | "0x7F7C5EB4708F" | "0x7F8F8043B989" | "0x7FF9EB838A33" | "0x7F4FAC341A6A" | "0x7F3D0BA9BBB7" | "0x7F181B82953A" | "0x7FC53B122083" | "0x7F9CF962B09F" | "0x7FD3853856D4" | "0x7F30ADEDAFF1" | "0x7FE8B81ED039" | "0x7F5001C14601" | "0x7FD267B6D865" | "0x7F167C3EADB3" | "0x7FCE998CD466" | "0x7FF8245DF44B" | "0x7F566ED2EEA8" | "0x7FFF4A22DD2C" | "0x7FCF672768A6" | "0x7F486807AF64" | "0x7FD260237A06" | "0x7F998453CD59" | "0x7F4424A7F9CB" | "0x7FE5C00EDA0C" | "0x7FE51EDEFA71" | "0x7F6F8D7A5B1B" | "0x7FED6107BCBC" | "0x7F356E923A48" | "0x7F71A0AEDB63" | "0x7FCD240F8D06" | "0x7F46FFA15C23" | "0x7F12808599F2" | "0x7FEC19F1D758" | "0x7F7AB92F8F0F" | "0x7FA47946FF48" | "0x7FF4F3689F6A" | "0x7F6AEF7316B6" | "0x7F32B0EE45E9" | "0x7F9E307FD66B" | "0x7F4126B2DED6" | "0x7F26D7666DD1" | "0x7F9A22D79820" | "0x7F795BE0F872" | "0x7F3EFD26E36B" | "0x7F013FED91E4" | "0x7F745B923EC0" | "0x7FCF441B5C9B" | "0x7FC9412A1B80" | "0x7F84285A0E05" | "0x7FB10234ACC0" | "0x7F34D976E355" | "0x7F667630CD5B" | "0x7FBFDB0DC1E6" | "0x7F76C3A9EA1E" | "0x7F3E0C5BEA7D" | "0x7F0CA5DED266" | "0x7F21910FBFD8" | "0x7F1F259D0461" | "0x7F09F426E0AF" | "0x7F8E0CB41036" | "0x7F479E751626" | "0x7FB73C5C7B55" | "0x7FF33B0E0936" | "0x7FA3491BA633" | "0x7F1B12EAA272" | "0x7FDFED48193A" | "0x7F12467A7C6A" | "0x7F613111DF75" | "0x7F4C66E7E4E5" | "0x7FBA855B82AF" | "0x7F035DB3D46F" | "0x7FF70082610D" | "0x7F0191381B22" | "0x7F6654ACAA92" | "0x7F4A7E5867CF" | "0x7F4577919E4A" | "0x7FA440A55958" | "0x7F6BF46320C8" | "0x7F2D11E6BFA2" | "0x7FD86BAC1BAE" | "0x7FE31209B76E" | "0x7F8E8BC72E85" | "0x7F0121367566" | "0x7F03620985C5" | "0x7F47E4B4D6F0" | "0x7F847B7705FA" | "0x7F535B77C408" | "0x7F96A8A4CB13" | "0x7F8188DEFC57" | "0x7F728E64BB85" | "0x7F02612BBDFE" | "0x7FB2A34AEC69" | "0x7FD9BB1ACC83" | "0x7F9D4D3F8126" | "0x7FF259609917" | "0x7F308D39F8CE" | "0x7FA48A3ED517" | "0x7F9F4CF79878" | "0x7F3FFBB09A73" | "0x7F538539977E" | "0x7FCB5A788AAB" | "0x7F5F261B7EE8" | "0x7FC8CFB8B29F" | "0x7F25EC483B36" | "0x7F6A79826044" | "0x7F7B4A4D364D" | "0x7FE2189AC90A" | "0x7FE6DA590F12" | "0x7FF002F922D3" | "0x7F9DAE5ED4BE" | "0x7FAEAA18ABF9" | "0x7FC094B683E0" | "0x7FF7BC421038" | "0x7F344AEF80CA" | "0x7FE9753430F2" | "0x7F253D3BD554" | "0x7F496E34795A" | "0x7F673F880A26" | "0x7FDFD1E33118" | "0x7F669D77F81D" | "0x7F8D0EBE16A9" | "0x7FC7A9CDB929" | "0x7FDCC01D7CFE" | "0x7F21C86CAE94" | "0x7FE033EB900C" | "0x7F65BFCD2330" | "0x7FD357F8C5B2" | "0x7F68A2A52E4E" | "0x7F4685095C86" | "0x7F20C9D2DD76" | "0x7FB7DBD89AA9" | "0x7FD8C38159B8" | "0x7FA28DC1CD24" | "0x7F298F749444" | "0x7F1E37B4FD4F" | "0x7FB13ABB5A8C" | "0x7FD792555539" | "0x7FFCA8360C02" | "0x7FDB97314564" | "0x7F1C29CF0D05" | "0x7F1966EA08DB" | "0x7F533C07ECFF" | "0x7FB50ECE7F85" | "0x7F9A56CC00F8" | "0x7F62F3A1EB04" | "0x7F4F0C583F68" | "0x7F1B1D257225" | "0x7F3FAF9342BF" | "0x7F4F2902BCC3" | "0x7F3FD2B4EA85" | "0x7FEE09447D26" | "0x7FD980A4F929" | "0x7F2A27EF9CC4" | "0x7FDD970E7496" | "0x7F5D3A291CE9" | "0x7F2B76132D6A" | "0x7F854909B2BA" | "0x7FE372F3EE20" | "0x7F9FF1EAD53D" | "0x7FAD04414592" | "0x7F62DBC33FFE" | "0x7FE6C4888751" | "0x7F1E6C241761" | "0x7FE6C5F15B0F" | "0x7F02A9AB1C25" | "0x7FCBC9BE29D0" | "0x7FD2014132C5" | "0x7F85CC7E1F88" | "0x7FE9F83B1EC2" | "0x7FA20B8FB994" | "0x7FCACADEECF0" | "0x7FB8DA314B72" | "0x7F18F0D53851" | "0x7F59AFADDE0D" | "0x7FE14F8E8AE8" | "0x7FC0A1C4C922" | "0x7F0EE38AA678" | "0x7F148F7336CB" | "0x7FDAEE287DDD" | "0x7FE52EFCD9FC" | "0x7FA19F29BC08" | "0x7F02D9E0B6C1" | "0x7F788738D32F" | "0x7FA7C48D4471" | "0x7F20140AAD54" | "0x7F62B63782A0" | "0x7FBAFBCE1DDC" | "0x7F564ED38CD2" | "0x7F7A031E8666" | "0x7F76FB87E538" | "0x7FE1FE0FE2F7" | "0x7F96B5E5F672" | "0x7F6C25A4C011" | "0x7F03A94B4D43" | "0x7F30E06F227B" | "0x7FBCE9EE4074" | "0x7F6B8D0CD65A" | "0x7FF7BD4F6D72" | "0x7F7EACF67C31" | "0x7FF4D3CF23B3" | "0x7F53928363D3" | "0x7F4F989EC8AC" | "0x7FCF57B34EC5" | "0x7F0A04BDF287" | "0x7F89DAC95BA3" | "0x7F1B5BC305B5" | "0x7FE7741410F0" | "0x7FBE627C2BC4" | "0x7F4D977EA6F7" | "0x7FE3E2D004B7" | "0x7FA40BBC0006" | "0x7F3F3ED69B24" | "0x7F8E1CE29828" | "0x7F25CE63BFA7" | "0x7FE619A5E91B" | "0x7FCB5D5ACDAB" | "0x7F83FB40D244" | "0x7F644E4E684E" | "0x7FBB8C54F9EA" | "0x7F756D0CFA6D" | "0x7F4DC5F94A47" | "0x7F7BABFCA6A9" | "0x7F13FF2B5626" | "0x7F1FFBA12B0D" | "0x7FC6204D60BF" | "0x7F63950C0813" | "0x7FD24D02750D" | "0x7FE4D735B8F4" | "0x7FD6E394E419" | "0x7F4D3BC4A9F4" | "0x7F1D36C612AA" | "0x7F26F595CAF4" | "0x7FC034D5FD6A" | "0x7F4B678E771B" | "0x7F491A72EF46" | "0x7F63FBCC40CF" | "0x7FD678E41C7E" | "0x7F86CB03DB6F" | "0x7F2B90029D65" | "0x7FE7CD6316B5" | "0x7F214DDB21F7" | "0x7FC7D642BD20" | "0x7FD7F7887444" | "0x7F7B7933C803" | "0x7F1F3E8DD460" | "0x7FF519B7AEC5" | "0x7F8FC08DAD76" | "0x7F009A8A1010" | "0x7F839FF17B66" | "0x7FB10F2C25F3" | "0x7FA4A64C9F04" | "0x7FC071F26701" | "0x7F54F7F061C3" | "0x7F71591F8612" | "0x7FC57E00AAFD" | "0x7F76A0A3135F" | "0x7F7B6C358304" | "0x7FDD8411242B" | "0x7FD6766110F5" | "0x7F3E0F728E81" | "0x7F05F746B5F1" | "0x7F33CE029DB3" | "0x7F90ABDDAE7D" | "0x7FE7C4213C44" | "0x7F0FA5B4A6DB" | "0x7F608E3487DB" | "0x7FC5AED5E4D5" | "0x7FC475FE7A87" | "0x7F376385D727" | "0x7F94C534272A" | "0x7F4FAA531044" | "0x7FA74FF02DEB" | "0x7F9D48518484" | "0x7F9707DF6A5E" | "0x7FE374BC6F28" | "0x7FF6A52580E9" | "0x7FC3CD3AA1D1" | "0x7FFE07D49E1B" | "0x7F501E17F7AA" | "0x7F969298D512" | "0x7FDBECD67872" | "0x7FBB1BA3C04D" | "0x7F6792D4AD54" | "0x7F93F191FBF8" | "0x7F77C3D22898" | "0x7FE52DA42ED6" | "0x7F5AF7D34C8C" | "0x7FE177617DD9" | "0x7FC844D17CCD" | "0x7F95A164CD34" | "0x7FB58E4522BC" | "0x7FA8D1F8ACA5" | "0x7F0E523E0642" | "0x7F71DCBC1CCD" | "0x7F1010B7D3C6" | "0x7F83FFD26114" | "0x7FFBAEB6F418" | "0x7F10E9FC84F1" | "0x7F6E581EDC40" | "0x7FD67422A660" | "0x7FB456CF86E7" | "0x7F870C235673" | "0x7F0DD7C2E9FE" | "0x7F19AE2A5DA6" | "0x7F498522486D" | "0x7F8538A984E5" | "0x7F1D8F185B7B" | "0x7FF0E04A6ABB" | "0x7F702FECCCAA" | "0x7F9E3B67DEC2" | "0x7FC709DD9F25" | "0x7FB197DE2AB3" | "0x7F0FD8B0A368" | "0x7F08499E6BCA" | "0x7FF5646678FD" | "0x7F7337B143BC" | "0x7F03B6E9D47D" | "0x7F7A3CBEAAE0" | "0x7F3AEA0389AA" | "0x7F0B3D1ABBDB" | "0x7F1568F38212" | "0x7FBF45D82CB4" | "0x7F95CFFFC2E1" | "0x7FF63F409EA6" | "0x7F11C07F981E" | "0x7F359C8C4006" | "0x7F50BEA6332D" | "0x7F58EDB1D314" | "0x7FA98A62C694" | "0x7FBC68245A6F" | "0x7FE006A4A709" | "0x7F2304BB0955" | "0x7FC84062D4B3" | "0x7F9A36243C38" | "0x7F250D249CFD" | "0x7FD2CA402A93" | "0x7F50F7998D20" | "0x7FF21D52C807" | "0x7FCA3DFF4842" | "0x7F76D35866E7" | "0x7FF544F9EE8E" | "0x7FCF33F64AA7" | "0x7FE72BFE56C3" | "0x7F7D2CBF2A7B" | "0x7F43D2E2F350" | "0x7FBE4044D850" | "0x7FF6409F2CBC" | "0x7FF7EEA9B7AF" | "0x7FB0D8880B1F" | "0x7F202B0C000C" | "0x7FC15A5AC4C8" | "0x7F43DFC9C5F3" | "0x7F21D3726DD0" | "0x7FB7C1599AE7" | "0x7F79D5C9FBC0" | "0x7F0DF7170D35" | "0x7F4201579770" | "0x7F0E875A896A" | "0x7F1D50B96634" | "0x7FF759A11AF5" | "0x7F2DA21D0E29" | "0x7F53D78D8D7F" | "0x7F8A5952D801" | "0x7FBEED3F7F6E" | "0x7F10BD627238" | "0x7FD0A02283C5" | "0x7F6FB71322A4" | "0x7F44130D2348" | "0x7F4854470248" | "0x7F8C95EFD4DD" | "0x7F965EB535D5" | "0x7F10BB5F00CC" | "0x7FAF040AB4BD" | "0x7FEBA180610E" | "0x7F639DF29364" | "0x7F0AB197363B" | "0x7F20D637DC96" | "0x7FA98873595B" | "0x7F60E77CF221" | "0x7F6F75DFA68F" | "0x7F3A08BD4E45" | "0x7FF245E2BD09" | "0x7F42F3961B97" | "0x7FF4F0037095" | "0x7F9B9426CF54" | "0x7F89DB3A0DB5" | "0x7FC25866C917" | "0x7F85B516809C" | "0x7F1F4ABAA342" | "0x7F540A2FA717" | "0x7F0565168948" | "0x7FC1A89F1BD9" | "0x7F5B90293CF9" | "0x7F7B072A1335" | "0x7F02E70897F1" | "0x7FB6392FEFF8" | "0x7F99967C2FA0" | "0x7FE083A1181D" | "0x7F1F76D597B1" | "0x7F24D4C8F28E" | "0x7F015B1843DE" | "0x7FAF02708E80" | "0x7FD021BEA5C5" | "0x7F5DCADC2E02" | "0x7F0323A4A362" | "0x7FA2AB778A4A" | "0x7F9EFC95AD4A" | "0x7FBDF74D352C" | "0x7FCAE473F95B" | "0x7F192AF35D85" | "0x7F089E5487B2" | "0x7F6061D547D9" | "0x7F970BCA78B9" | "0x7F33FABAE19E" | "0x7F3FFAC17A82" | "0x7FBE4C50A2A5" | "0x7FDDFE6D8957" | "0x7F9A9E0A7AE4" | "0x7FEADBFD7075" | "0x7FB333873A4C" | "0x7FE4CCAD0A59" | "0x7F406BF4DEC7" | "0x7FADE61438E9" | "0x7F8E20F08502" | "0x7FAB2FE4E497" | "0x7F02102ED5A1" | "0x7F0AC2D5E926" | "0x7F63E3D89849" | "0x7FA41FB728A6" | "0x7F0150BC314F" | "0x7FC614CAB318" | "0x7FDE35F3BDD4" | "0x7FD38197B7F7" | "0x7F3992DB729C" | "0x7FC09EFFD7BB" | "0x7F451861E3EC" | "0x7F2656CB85C8" | "0x7F41112667A7" | "0x7F0215345342" | "0x7F604D4D0B18" | "0x7F2EA380DEAF" | "0x7F3B3F037927" | "0x7F593E3733D8" | "0x7FE581378999" | "0x7FD78A8B8B99" | "0x7FC3423E7D96" | "0x7FF82A73583A" | "0x7F2FC32A1080" | "0x7F3D92CF7E2A" | "0x7FB684A8D3DA" | "0x7F04F1CF4609" | "0x7F813AB03722" | "0x7FEAC7A53FAA" | "0x7F872F539697" | "0x7FC8518814D5" | "0x7FD35422E50C" | "0x7FE34FDD50E0" | "0x7FB054B3F928" | "0x7FAC25BB702A" | "0x7FE79ED7A74C" | "0x7FC738633EC5" | "0x7F4905DC249E" | "0x7F5BE44A54EC" | "0x7F7EA8279B03" | "0x7F40BED77BA9" | "0x7FAFE20221C8" | "0x7FE9F58D7247" | "0x7F159286DB04" | "0x7F6B7790E2A4" | "0x7F2014686B19" | "0x7F8608538C1D" | "0x7FDF2C935267" | "0x7F5802EA5815" | "0x7F01B9B9C6AB" | "0x7F681B779DD8" | "0x7FDD8BB6BA6F" | "0x7FB42036E1FD" | "0x7F502C83DDCF" | "0x7F49A9BCA8DB" | "0x7F72D682CC49" | "0x7FE32B35B260" | "0x7FB425A7E972" | "0x7FC4B39DEE4E" | "0x7F3D5BEFCF1D" | "0x7F957E785CF5" | "0x7F631E1F56B1" | "0x7FDA16694E0A" | "0x7FBC6C49A323" | "0x7F3DCCF5AC6A" | "0x7F4BAB8EA9E8" | "0x7F762C66FA80" | "0x7F570D3518C1" | "0x7FF2F1D52EA8" | "0x7F24BBFEC5D9" | "0x7FD42DDC4105" | "0x7F17681BDA74" | "0x7FBAB5A3AFEF" | "0x7F70C69AB666" | "0x7FF83D3CE9C8" | "0x7F777DB044E9" | "0x7FFBCFB0BE1A" | "0x7FB7895D0CC7" | "0x7F061EA04902" | "0x7F5500720257" | "0x7FB51F409F4E" | "0x7FA93C0DA9F5" | "0x7F51FDE82839" | "0x7F2008BDCE63" | "0x7FC872DF0DF0" | "0x7F8D7859C0CC" | "0x7F531955BAAE" | "0x7F147078C90F" | "0x7F82DAC8AD92" | "0x7F03D9FBEB33" | "0x7F3AD0E6B081" | "0x7FA0F9A344B8" | "0x7F153DA4B879" | "0x7FAD7832D544" | "0x7FF34C199C95" | "0x7FDA57032E2C" | "0x7F6F9FE4B436" | "0x7F40C7F35645" | "0x7F9157D4D553" | "0x7FCDD350FD89" | "0x7FCACCEB6B3A" | "0x7F79A9342A42" | "0x7F7749DD842B" | "0x7F2C5195E757" | "0x7F0C593DEFC0" | "0x7FDFB9DC6850" | "0x7FBFCB7034E9" | "0x7FC31AFF0707" | "0x7F9EB0E76BFA" | "0x7F90AFA522FA" | "0x7F6BDC8DFED1" | "0x7FDB3EA88334" | "0x7F7A26753B1E" | "0x7FB7AFA1B148" | "0x7FBAF1A58D00" | "0x7FCD683B00F5" | "0x7F58B5F065A4" | "0x7F53CE445FD9" | "0x7F721F9C9340" | "0x7F43B9F91754" | "0x7F42FD335DAF" | "0x7F3DB8803FBE" | "0x7F8747753C10" | "0x7F34F246DC7B" | "0x7FA923D33599" | "0x7FB4FC5C39A7" | "0x7F90CF670620" | "0x7F7E77C46EFB" | "0x7F52793E2235" | "0x7FCFADF612FC" | "0x7FCD69BC1382" | "0x7F19D5A3D44E" | "0x7FE2671C65B0" | "0x7F83287FB664" | "0x7F6543E80D95" | "0x7F7B2FCA69DB" | "0x7F2F6FAEC58F" | "0x7F17C301458A" | "0x7F6537C80E2D" | "0x7F1CBFA2A209" | "0x7FB494555B6A" | "0x7FA5DF48809B" | "0x7F2CCF4BE04A" | "0x7F46786DB032" | "0x7F3E855C5DC1" | "0x7F4BAD5A5913" | "0x7FF559A8B66F" | "0x7F48B2A5F55B" | "0x7F9EF29F193D" | "0x7F21E9951659" | "0x7FA82ED55358" | "0x7FC76D400B19" | "0x7F89B746CB7F" | "0x7FFF389CE9CB" | "0x7F8273675067" | "0x7FF15CD727B7" | "0x7FF252DAFB51" | "0x7FCE943565C3" | "0x7F665A256B16" | "0x7F67590266E4" | "0x7FFE63C8CD3E" | "0x7F277726DF77" | "0x7F79F357ED24" | "0x7F137058999A" | "0x7FC907996D3E" | "0x7FA1CFE68902" | "0x7F9A0177573A" | "0x7F5C18022592" | "0x7FB85201B78B" | "0x7F8C5EAA0D98" | "0x7FCBDBBF5752" | "0x7FF90D012EA5" | "0x7F936D0F4ECC" | "0x7F8E2C0AC1D0" | "0x7FAB6C34BEB2" | "0x7F66B8BD45F7" | "0x7F3371305B3B" | "0x7F5E22CE6525" | "0x7F0077AFB1AB" | "0x7FAD87CF128F" | "0x7F2743205665" | "0x7FE1467120FD" | "0x7FC1AFD7E0E6" | "0x7F6BDE7E2D26" | "0x7FC12C150646" | "0x7FBB68930B02" | "0x7FDF5B43D20E" | "0x7FA9F1E967F1" | "0x7FC064C4007F" | "0x7F38AA45C992" | "0x7F0CA6512C97" | "0x7F2D0CFB966F" | "0x7FC8D8112687" | "0x7F05C908971A" | "0x7FB8E9C6B57F" | "0x7F64F22340FB" | "0x7F7F0368FC64" | "0x7FBDE69DAEED" | "0x7F6640974A9D" | "0x7F7346ACBF99" | "0x7F47BE470339" | "0x7F49C54C1CE8" | "0x7FFF05DF7664" | "0x7FC65F11BE0E" | "0x7F464540116D" | "0x7F248CC59059" | "0x7FD523D9B8CB" | "0x7FFA027673A3" | "0x7F35F05B0DF8" | "0x7F95C1A5A5E4" | "0x7FDCE21B4D4B" | "0x7F6A91AC65F9" | "0x7FFA8629460F" | "0x7FEE942060CC" | "0x7F26E31373F1" | "0x7FDF3C32F0D3" | "0x7F35CBF01928" | "0x7FEE2BF82677" | "0x7F64B03C3FC4" | "0x7FDAD94C5FCF" | "0x7F90A9441C7D" | "0x7FC183B7E639" | "0x7F4F82A2F1AE" | "0x7F39E7DC24D2" | "0x7F60ECED12C4" | "0x7F471A45C8F5" | "0x7F4AD4B1CD64" | "0x7FFC1E18EC8A" | "0x7F5F13CB48DB" | "0x7F9661101B33" | "0x7FA49E41B6EF" | "0x7F7CA903DD79" | "0x7F1319C27FCC" | "0x7FDD3732F661" | "0x7FFBB4B9C7AC" | "0x7FA0C91E93E5" | "0x7F5B2A45CFAF" | "0x7FD14E867C52" | "0x7FBD9FDC8752" | "0x7FBF01A14A89" | "0x7F2677E3692E" | "0x7FAA416D7331" | "0x7F94AE48DCC5" | "0x7F552E12FE60" | "0x7F0A0022873C" | "0x7F49DC2696F2" | "0x7F0D781E1AC3" | "0x7FEE1AF116A1" | "0x7FBB7911D129" | "0x7FF81F29FABC" | "0x7F333686B813" | "0x7F27C62684F9" | "0x7FBA51BD5B1E" | "0x7FCA155FDA95" | "0x7F0C7DEF36B3" | "0x7F314EB1C72E" | "0x7FE3880EE352" | "0x7F37F92BCC70" | "0x7FA31686F0E5" | "0x7F7ADE1B9813" | "0x7F87AFC8A789" | "0x7FBF21FC24EA" | "0x7FCC37EA9709" | "0x7F1C53B248A2" | "0x7FDAFAF3CB08" | "0x7FA287B1B4E5" | "0x7F054CBE123D" | "0x7FE573A89307" | "0x7F7E6397C4FD" | "0x7F293DB90FBB" | "0x7FC7A16C82A1" | "0x7F5C58E2BDD2" | "0x7F70064806F6" | "0x7FE86ACDDE94" | "0x7F9B04ED8507" | "0x7F70D0626335" | "0x7FF2CB5EA702" | "0x7F5CEF76241B" | "0x7F771080B029" | "0x7F7F5B2579D3" | "0x7F239957CCE4" | "0x7F6DCEBB9EE2" | "0x7F9868353FC3" | "0x7FBCB5C0161C" | "0x7F87AF4A6469" | "0x7F947D7606BF" | "0x7FAD97217200" | "0x7F118DF69930" | "0x7F64B81D6132" | "0x7F90E5500CE9" | "0x7F28BB3F0B23" | "0x7FAB6EE636CF" | "0x7FD6A94B47D3" | "0x7F67A3A5C1DD" | "0x7FD82FCFD465" | "0x7FFD7EFF0742" | "0x7FAA8DB87D82" | "0x7F8604694AED" | "0x7FA32AD3B77E" | "0x7F2A3DE72308" | "0x7F85F85ABB49" | "0x7FDDF4D6E995" | "0x7F9D1858748E" | "0x7F980527312E" | "0x7F38D686B53C" | "0x7FF38A07348C" | "0x7F7AB52ED1DF" | "0x7F61A5E04B7B" | "0x7F20C9DAA99E" | "0x7F3FD0D96E60" | "0x7F316CD7F735" | "0x7F5A6BDC09E0" | "0x7FA5B9EFBF3F" | "0x7F4AA7F89C0D" | "0x7FC77B2D79A1" | "0x7FA9554F35CE" | "0x7F32430E2029" | "0x7F541FE5BBE2" | "0x7FB31BE71AD6" | "0x7F695882CB89" | "0x7F265477F51D" | "0x7F21679B24DE" | "0x7F97E50FED03" | "0x7FC77033304F" | "0x7F2C60FFC47E" | "0x7F7450F6D609" | "0x7F02061BCC62" | "0x7F0736333C85" | "0x7F1B62F0E35A" | "0x7F75E7FA36E2" | "0x7F0FE76409FD" | "0x7F00EA197A45" | "0x7F59EDEA4268" | "0x7F9B84D14281" | "0x7F87D4B1BF60" | "0x7F37FD6FB355" | "0x7F624F5B0D6C" | "0x7F0071DEEBCC" | "0x7F03FC72496F" | "0x7F045EACA5BC" | "0x7F2AC8D16F34" | "0x7F135F76DB2D" | "0x7FAC408FC308" | "0x7F06DF3DDF6E" | "0x7F4252AB3286" | "0x7FA744CE3ADD" | "0x7F4C380F2B45" | "0x7FDE8FDE9639" | "0x7FBDB0350CB9" | "0x7FE9B43690D1" | "0x7F8755C93373" | "0x7F56ACC95074" | "0x7FE6B5E68E21" | "0x7F6E4DDB3DC3" | "0x7FB471BDA1C1" | "0x7FEFDB8B88A8" | "0x7F218AA8FEFF" | "0x7F91132CB2A8" | "0x7F1C20DBF680" | "0x7F2CCE109C58" | "0x7F4623850443" | "0x7F6B0F4F27F2" | "0x7FA116B881D0" | "0x7FCC4245E023" | "0x7F01FEC74A2F" | "0x7F4B0EA20F87" | "0x7F7468BD9F3C" | "0x7F68E23E6857" | "0x7FB0BF82872A" | "0x7FAB3F9D63B9" | "0x7F7F4488FF1C" | "0x7F5276279461" | "0x7F1B75665851" | "0x7F55DC5153E6" | "0x7F1FD087D363" | "0x7F33A08A2E10" | "0x7FD96687F336" | "0x7F79C9615249" | "0x7F1E20D24FE1" | "0x7FE943160A3D" | "0x7FD420E6C1DA" | "0x7F7F3BADF201" | "0x7FAAD73CD19C" | "0x7F3FB7915F9A" | "0x7FD2DB84AE23" | "0x7FDC2929222C" | "0x7FE45EDED022" | "0x7FE0C202894A" | "0x7FED629B1410" | "0x7F4EFD21861D" | "0x7F461956E19B" | "0x7F7FC12CF462" | "0x7FB7AE1A3F86" | "0x7F5BF016E2F7" | "0x7F278A47C281" | "0x7F564C95F1D3" | "0x7FD50F0F2B1B" | "0x7FBD44AD1DAA" | "0x7F4E79EEDFCB" | "0x7FE74F2E2574" | "0x7FE3CDAE7B93" | "0x7FEA4055DB12" | "0x7F9E4AF6C7B0" | "0x7FEC041D09B5" | "0x7F93D10EA8F3" | "0x7FFDF0B43A96" | "0x7FEF4B34B676" | "0x7F837BEFE212" | "0x7FCCCE794E42" | "0x7FD00BA0DA24" | "0x7F99995D8500" | "0x7FFCA699D010" | "0x7F28D5C5FB30" | "0x7FE0DAA38E21" | "0x7FD4FA8C5706" | "0x7FA9F1690084" | "0x7FA36BED0E31" | "0x7FBF249BE5C5" | "0x7FCD2A1B383E" | "0x7FCDDB7DB8D7" | "0x7F8B48BA0A52" | "0x7FB1901E4F30" | "0x7F31D04BE4FD" | "0x7F1542E633ED" | "0x7F1A4129E015" | "0x7FBBE9C2474A" | "0x7F976190E26D" | "0x7F70E5897FB0" | "0x7FA9F05363BF" | "0x7F80EB51A105" | "0x7FE386ABA400" | "0x7F57E4750476" | "0x7FB20787C12B" | "0x7FFD36C78A7B" | "0x7FBFB48F4E38" | "0x7F45A73DC4A6" | "0x7F732D499F8C" | "0x7FC7F1FA9A03" | "0x7F5119732C05" | "0x7FD301F932D6" | "0x7F5423AC1044" | "0x7FAE67713B9A" | "0x7F7207F220AF" | "0x7FAEFD74D6E7" | "0x7FB56DB85328" | "0x7FE21A90D506" | "0x7F8C986FE424" | "0x7F990E70EA7D" | "0x7F8F65DABE55" | "0x7F32BC5C60D4" | "0x7FBBC82CF000" | "0x7FC656526990" | "0x7FF360AC03E4" | "0x7F85BC7B4407" | "0x7F62CC744514" | "0x7F067E9E6863" | "0x7F327A379089" | "0x7FAFFD562FE4" | "0x7FA2626BEA38" | "0x7FBBB52453D0" | "0x7F7F3FA8F43A" | "0x7F1BF82709FF" | "0x7F933F9E5D2E" | "0x7FC54F406206" | "0x7F51FABE57A3" | "0x7F932A9E89F0" | "0x7FB45B00BDB7" | "0x7FB01ABDEDF2" | "0x7FBC679D47CB" | "0x7F078503B5B9" | "0x7F509EA81719" | "0x7F30B8210343" | "0x7F4972887508" | "0x7F8B9AE2D037" | "0x7F025564A9CB" | "0x7FFEB7CF5DCE" | "0x7F6A84FBAAD1" | "0x7F6826D17F21" | "0x7F6D5E5B1EB8" | "0x7FA4E29021D8" | "0x7F88C5A1E936" | "0x7F4F358FA9D7" | "0x7F73B69AAA6D" | "0x7F7F45CB3E81" | "0x7F247305353D" | "0x7F862A96940A" | "0x7F9CF06D06AB" | "0x7FFF36A01004" | "0x7FAF8163D7C8" | "0x7FB31DA1DC85" | "0x7FE444074B18" | "0x7FE315CA7FBF" | "0x7FF6BD70F93F" | "0x7F1A80F99B09" | "0x7F86624CD8FC" | "0x7F22531D24ED" | "0x7FE6B7FCEA31" | "0x7F8409EBC0FD" | "0x7F87B6D451E8" | "0x7F4020EED740" | "0x7F82B2AD734A" | "0x7FB6F8D9BAED" | "0x7F5ADC9B0AAE" | "0x7F9527CF9AD7" | "0x7F65CBCABD76" | "0x7F104C44D112" | "0x7F65916F1E44" | "0x7FF2CE435917" | "0x7FF369E7E8B5" | "0x7FE0DAF4AA91" | "0x7F0E5218FA59" | "0x7F3AA90EB439" | "0x7F7E85E74B6E" | "0x7F6AEA2F2BEE" | "0x7F821E572861" | "0x7F3B31F82F35" | "0x7F59D83CCB38" | "0x7F056ACDBC70" | "0x7F65EEEA10B2" | "0x7FC8FF5B4A67" | "0x7FA999DF2847" | "0x7FDD3A897084" | "0x7FE6FF410879" | "0x7FA150556854" | "0x7F1FF3285E2F" | "0x7F01306987AC" | "0x7F1CAA9F6A13" | "0x7FE232B64E83" | "0x7FF7D611B550" | "0x7F5D4901FB04" | "0x7FD97F155F2E" | "0x7F1F85CE88CC" | "0x7FEEEE27EDF8" | "0x7FFEA07C6DE3" | "0x7FAC5350C9BE" | "0x7F6A86CA9984" | "0x7F47351AE589" | "0x7FFF9FF90B2B" | "0x7F1652195C6E" | "0x7F29AEC4538C" | "0x7F5A34EF0D7E" | "0x7FCBB0E4A4C4" | "0x7F099E773D50" | "0x7F6FD3CB3A48" | "0x7F21D7BC901F" | "0x7F4C8E08E9B5" | "0x7F914822A14E" | "0x7F049747C226" | "0x7FE848EF9628" | "0x7FA9FC9D483D" | "0x7F12DE79F07B" | "0x7F6C69C0667B" | "0x7F45A0A196A2" | "0x7F3FB4C2D4BA" | "0x7F7D7360E285" | "0x7F1611E5841C" | "0x7F018254588A" | "0x7F94C0244E82" | "0x7F02525768B3" | "0x7F36BD095F9A" | "0x7FE0E44A0575" | "0x7F48D770DEAF" | "0x7FA02BCDCFC3" | "0x7F66AFDCBC5E" | "0x7FF89017A2D0" | "0x7F871CA855B0" | "0x7F30F1211DE4" | "0x7F094F284FE4" | "0x7F106F134DD1" | "0x7FEB854107F1" | "0x7F6930405377" | "0x7FEB63CD13B1" | "0x7FF0B073AFF9" | "0x7FA9165729CC" | "0x7FF406361EBD" | "0x7F4C2D759EA0" | "0x7F315A93621F" | "0x7FED914D27DB" | "0x7FD3ACFAF1A6" | "0x7F9830256491" | "0x7F89A5E98308" | "0x7F1C315DD849" | "0x7F7452905C66" | "0x7FCA5F23177D" | "0x7FB5744DF511" | "0x7F55EDD96306" | "0x7F1FAD77A1E4" | "0x7F20CE794231" | "0x7F37F17B13DF" | "0x7FA045AB17F0" | "0x7F866B8878DB" | "0x7F3785351AAD" | "0x7F8023F70A45" | "0x7F9CAEE8F82F" | "0x7FFBB4B37DF4" | "0x7F231C32098D" | "0x7FBEC93D6D5F" | "0x7F39AA16177A" | "0x7FE30FBB4F43" | "0x7F51ADCA562B" | "0x7F9E17399EBA" | "0x7F210B72B66B" | "0x7F9C13184376" | "0x7F4FA296779C" | "0x7FE1EE28A86B" | "0x7F202B5F1F45" | "0x7FD64F6574E9" | "0x7F8391403325" | "0x7F4939A144DD" | "0x7F0544F56A1C" | "0x7F0C1015421E" | "0x7F8E779F132C" | "0x7F61809C92D0" | "0x7F66D87E0159" | "0x7F064FDFFBFA" | "0x7FF58AA789A6" | "0x7FEDF0ACA37D" | "0x7F12A6B8F99F" | "0x7F38840E72BF" | "0x7F3F5692776E" | "0x7FBC4BAF4A81" | "0x7FFCC8F025AA" | "0x7F90D9B26219" | "0x7F7B93E3FC20" | "0x7FCAC91DD71B" | "0x7FAA2A1443BB" | "0x7F6A6D19BE6A" | "0x7F8648FCCF45" | "0x7FCDDE7DB220" | "0x7F9C493771BD" | "0x7F116581A3A1" | "0x7FAF153F9542" | "0x7FDF95775077" | "0x7F1AE9CA1EFA" | "0x7F7440B9EEBF" | "0x7F19780D18FD" | "0x7F42CA16F3F5" | "0x7F851E2AFC17" | "0x7F70E0BD026C" | "0x7FD8F799D113" | "0x7F50E2A6496A" | "0x7F16817822B1" | "0x7F7A54835B0B" | "0x7F722FBE1ED6" | "0x7F17D0D8E764" | "0x7F9A31BFBC64" | "0x7F5F3B11F45A" | "0x7FF4C8FEB077" | "0x7F40ABAC98AC" | "0x7F5AED80A279" | "0x7FE8DD20EFF0" | "0x7F2CDE7860D8" | "0x7FE2385BFFA4" | "0x7FC9DF00D7B3" | "0x7FDA5CFFEBCA" | "0x7F9EF2DF2966" | "0x7F7F7A2DF42C" | "0x7F5811D6B48E" | "0x7F818270C443" | "0x7FF1BCBC834B" | "0x7F474E9EBE0C" | "0x7FDA4251B3AD" | "0x7F2A4FA55447" | "0x7F15AF62FB79" | "0x7F551B93FB33" | "0x7F58E1D1C2FA" | "0x7F65BF38800C" | "0x7F228B4A0ABE" | "0x7FD454CB7464" | "0x7FEA2A69F4C6" | "0x7F3E6DF59B89" | "0x7F15E2CB2C86" | "0x7F4744CBC334" | "0x7F7EBB6BF651" | "0x7F40327C29AC" | "0x7F9DB9E9A8FA" | "0x7F21169A12A2" | "0x7F5CAFC1918F" | "0x7F016C435176" | "0x7F7C821BD4B6" | "0x7FE2B494EAB3" | "0x7F193B025D59" | "0x7F1F92EBDB73" | "0x7F1DB4962936" | "0x7FFC3A38C9F0" | "0x7F390E3ABC58" | "0x7F25AF356332" | "0x7F7C1D524DFE" | "0x7F46AF5BD52C" | "0x7F1B4013FC81" | "0x7FFC5F49482E" | "0x7FEC9BD15921" | "0x7FA736EA4EB1" | "0x7FC8DC5AA806" | "0x7FE1B000A230" | "0x7F937D065A99" | "0x7F813FA158A3" | "0x7F815BD77351" | "0x7F121CC504EF" | "0x7FFEC74CFC55" | "0x7FC4B946F3D1" | "0x7FEA14A1529F" | "0x7F8AE32E2B20" | "0x7FB090CCB212" | "0x7F831EAFD7F0" | "0x7F9E4E0D66F3" | "0x7F71859081C7" | "0x7F2FF9D109BD" | "0x7FC24ED504B1" | "0x7FD289D34FE1" | "0x7F07801BE6D9" | "0x7FDDB7F1AFF8" | "0x7FDA6B88162A" | "0x7F423BD1D811" | "0x7F15EF419E3C" | "0x7FFC2ED8A658" | "0x7FED8FCEBA1A" | "0x7F1671DAABFB" | "0x7FB7ECFD50EB" | "0x7FA40FD332AF" | "0x7FBF5127711B" | "0x7F95EB04E928" | "0x7F6E4B365B0B" | "0x7F0F6D317A0A" | "0x7F103A8DBE6F" | "0x7FC2427F1A5F" | "0x7F5E5E5FEC92" | "0x7F853C96BF3C" | "0x7F06DFA653AF" | "0x7F5D656AA4ED" | "0x7FFE77D61316" | "0x7FEF1F057718" | "0x7FA6D3F0639B" | "0x7FF0C1DE0798" | "0x7FB2F22DBD9A" | "0x7FCC5D2AEB16" | "0x7FC78C771E0F" | "0x7F2180C478B0" | "0x7F0F8CD3D745" | "0x7F078DECD1A6" | "0x7FED8696EF86" | "0x7F2C4BF0D15D" | "0x7F85F2615886" | "0x7F3AAC6DEE26" | "0x7F5B20726067" | "0x7FF88BC16FB8" | "0x7FD0B09E9EB8" | "0x7FD6766CA733" | "0x7FB80F1EEE18" | "0x7FB6A2240D13" | "0x7F72F5B225EC" | "0x7FCBA8DD82E7" | "0x7F843264BFA2" | "0x7F362A408840" | "0x7F845DE08586" | "0x7F479CFD9E6B" | "0x7FAE567B1809" | "0x7F0F21AB4AEE" | "0x7F93E35A09C0" | "0x7F5D5AF0203A" | "0x7FB69EEFFA01" | "0x7F8644146427" | "0x7FCD0500C0C9" | "0x7F45F43D18ED" | "0x7F353A3CE36A" | "0x7F0B161B8CDB" | "0x7F1BE63BFE0C" | "0x7F2CBAE0C9CF" | "0x7F12AE71A593" | "0x7FA7DB268503" | "0x7FB4EDFF704A" | "0x7F31922D56C9" | "0x7F64C4D1431E" | "0x7F78A1F0BFA8" | "0x7FA1D20E3060" | "0x7F0F9EFB4110" | "0x7F28B90D60D5" | "0x7FC10CB817DA" | "0x7F21D8D48255" | "0x7F18121081C7" | "0x7FEB959AFD87" | "0x7FDA11849B3D" | "0x7F07B5B8979B" | "0x7F25B9A62426" | "0x7F910CE95995" | "0x7FDF58CF8E60" | "0x7F676CF00A35" | "0x7F48D3AEFCAE" | "0x7F2B24AF77A8" | "0x7F2AE9D9773C" | "0x7FBEF2D0E488" | "0x7FADB5094CE0" | "0x7FE86FC1618E" | "0x7F67ADBC723D" | "0x7F17AC20F441" | "0x7F2E452C6BD6" | "0x7F627BB47F00" | "0x7FDEB58FA06A" | "0x7F38BFF1B7CC" | "0x7F95FE5D18D3" | "0x7F8ED17FDA41" | "0x7F584D238A02" | "0x7F1985EE0934" | "0x7F2513DFCF9A" | "0x7F342DCD058E" | "0x7F3413B83EB4" | "0x7F9ECF563754" | "0x7F2854955454" | "0x7F0CDA7BF81A" | "0x7F9C9F0A7840" | "0x7FCC8A41301E" | "0x7FF4E0324E93" | "0x7FB2D5B5602C" | "0x7F11D2B45D3D" | "0x7F0E10DA4CC7" | "0x7F645A5593E0" | "0x7F9749EBF61E" | "0x7FCD54EF0DFA" | "0x7FBA5B959855" | "0x7F80CB381CFA" | "0x7FE1FE72B2D7" | "0x7F6FB5A6C998" | "0x7F10751AFC9E" | "0x7FD247FB8ADC" | "0x7F35E27273E2" | "0x7F0F05271453" | "0x7F6F7B94A35D" | "0x7FC60C46BBD6" | "0x7FCF41062BB8" | "0x7F48CE6E6FAB" | "0x7F06E8E88252" | "0x7F0300C042E2" | "0x7F28EA208CD5" | "0x7F56CEB03FAA" | "0x7F1F23AEF96F" | "0x7FA82255779A" | "0x7FBB9F0CA2AB" | "0x7FF4D33FC3E3" | "0x7F13A2FB1436" | "0x7FDA978CB4D9" | "0x7FA4916E3626" | "0x7F682CB082C9" | "0x7F164D382ABB" | "0x7F40DF970672" | "0x7F53D2E12141" | "0x7F0EF94688CF" | "0x7FCA6A6793CB" | "0x7F4E2BD4273A" | "0x7F95DE61231F" | "0x7F31108F180D" | "0x7FE923D02FE4" | "0x7FC545A436EC" | "0x7FCC04B9350B" | "0x7FDCFEDBC947" | "0x7F78F14AF410" | "0x7F4800BD2980" | "0x7F1A3BD563F4" | "0x7F286DFD934A" | "0x7F4BA8EE1252" | "0x7F74D58CC9EA" | "0x7F8D22810CC7" | "0x7FDE8071E0A6" | "0x7F672FE484C4" | "0x7F859DA65B2C" | "0x7FBB306C0948" | "0x7F07E1E02E1E" | "0x7F9673CFE7DF" | "0x7FA75E81D255" | "0x7F5955281BB9" | "0x7F4146B3D215" | "0x7F084EDCEB7F" | "0x7FADE906BDC4" | "0x7F90B7F78E76" | "0x7FA4CB5D0C21" | "0x7FE47D0752FC" | "0x7F463E78EA4D" | "0x7F3D6CA26D29" | "0x7F303942ADF0" | "0x7FF05E907B99" | "0x7FC2AD04D4D1" | "0x7F8C7566A116" | "0x7FF0AC67100B" | "0x7F41E3FAE5D7" | "0x7FE26B5139B4" | "0x7F41C4F994CD" | "0x7F3E67F9D06D" | "0x7FFBAE28A568" | "0x7FC14FFA6A18" | "0x7F2AC42AAEB1" | "0x7FA7A3C70A2A" | "0x7FA54D5E4305" | "0x7FBB8C434797" | "0x7F60B0E38578" | "0x7F7075219D6A" | "0x7F7531A86175" | "0x7F02682FEFDB" | "0x7F22F9DA540D" | "0x7FC8E49E57BA" | "0x7FEE2B94EEDA" | "0x7F155D258693" | "0x7FF90B257D60" | "0x7FCD223A76AE" | "0x7FFC869E1709" | "0x7F58524E7D86" | "0x7F7CD0379F62" | "0x7FDBCB9EAF8D" | "0x7F6F6EF9C2AD" | "0x7F70ADA7C770" | "0x7FBCB02452BE" | "0x7F32004D7803" | "0x7F1CA16E16A0" | "0x7F62A0E72557" | "0x7F31C8FF4E0B" | "0x7F55D7DC6299" | "0x7FDF8C15B331" | "0x7F82780CF23D" | "0x7F23A42E595B" | "0x7F12F5013C05" | "0x7F38B881F75E" | "0x7F88710F975B" | "0x7FF05D024DFD" | "0x7F4D03ACE4B3" | "0x7FB0C4958DEE" | "0x7F326C759531" | "0x7F1A9B927FA3" | "0x7F5E1F0C9C02" | "0x7FB29B325FF9" | "0x7F5EEAE31B7E" | "0x7F335F0A76FB" | "0x7FE896E03837" | "0x7F5E5F44E6E9" | "0x7F495CE27E6B" | "0x7F163892BB20" | "0x7FD4E5122673" | "0x7FB17842C0DA" | "0x7FCEF4CD216E" | "0x7F630AFCC6CF" | "0x7FB00C869C79" | "0x7F530DE01A28" | "0x7F8F51CC245C" | "0x7F591F0C832A" | "0x7FCD92B5C03E" | "0x7FC6BF9E149C" | "0x7FFAE8FA0C49" | "0x7FF690C2E7B6" | "0x7F7879A557EE" | "0x7F3F0B7EC3CB" | "0x7F4C0FEF6F8B" | "0x7FD402225070" | "0x7F1CF0E9FE65" | "0x7F571E320B32" | "0x7FB1AFC060D7" | "0x7FF9E95EBA17" | "0x7F761CBEBBA0" | "0x7FBFE47D3A0A" | "0x7F38CEC1E0AC" | "0x7F3602F161D9" | "0x7F7B01A4380D" | "0x7F527B312037" | "0x7F677ACE9EFA" | "0x7FE9D0A1049E" | "0x7FC16C3BB035" | "0x7FD8E5E407A6" | "0x7F0206D952C0" | "0x7FA607DC39B8" | "0x7FD5A419F4E4" | "0x7F44A262E293" | "0x7FB18D611DD2" | "0x7FAFCEC20C28" | "0x7F0431BEA3F3" | "0x7FD51E93929D" | "0x7F4ED6E63B08" | "0x7F6FE2F27157" | "0x7F6101866CBE" | "0x7F985E6A956C" | "0x7FC1C35D7336" | "0x7FF4BD6AF64F" | "0x7F810FD7F18D" | "0x7F5E352972F9" | "0x7FB6DD987094" | "0x7FE35FDD89D9" | "0x7FFEE343BC8C" | "0x7F4F7AA7CBFF" | "0x7F81D2D4B929" | "0x7F21EE1E27D5" | "0x7F35BFB40504" | "0x7F4742B2202C" | "0x7F0A7F957E78" | "0x7F2F139217CD" | "0x7F3A773038A7" | "0x7FCD87C15853" | "0x7F8A6C4883AF" | "0x7F6B7EAEEF76" | "0x7FFF8A3D4E24" | "0x7F7DFF509042" | "0x7F10EF1CB396" | "0x7F8CB32DBA90" | "0x7FA5CAE80314" | "0x7F6BF1D94029" | "0x7FD7160D3777" | "0x7F504700C0FE" | "0x7F79DA130B73" | "0x7F63BEF1FCC9" | "0x7F974FB3B484" | "0x7F384CA82DB8" | "0x7FCFB7C0EE80" | "0x7F844817E60C" | "0x7F51AED2CACA" | "0x7F71FA72295C" | "0x7FFD0E8A3C91" | "0x7F1607628CEE" | "0x7F7426E31724" | "0x7FB2682EE2C1" | "0x7F35F4ACD278" | "0x7F17A62BB3C0" | "0x7FBF38162D35" | "0x7FFA171D27A9" | "0x7F301ECD7EE6" | "0x7FD180CE2DE1" | "0x7F9038DD5249" | "0x7FF129F4B326" | "0x7F4FBF08F957" => {
            if body.advisoryIDs.iter().any(|advisory_id| !is_expected_advisory_id(advisory_id)) {
                return Err(AttestationVerificationError::AttestationError(body.isvEnclaveQuoteStatus));
            }
        }
        "SW_HARDENING_NEEDED" => {
            if body.advisoryIDs.iter().any(|advisory_id| !is_expected_advisory_id(advisory_id)) {
                return Err(AttestationVerificationError::AttestationError(body.isvEnclaveQuoteStatus));
            }
        }
       "0x7F4CC0188C1F" | "0x7FDD4A530A77" | "0x7F0881AED481" | "0x7F9B1E4BA19B" | "0x7F58BD509461" | "0x7F05093E707D" | "0x7F980DB48407" | "0x7F0A96E98688" | "0x7F5C5C43B98D" | "0x7FC4B35CA63A" | "0x7F15ADAA92B0" | "0x7FFE9DEE9535" | "0x7FE253C92131" | "0x7F2AEB71DB9A" | "0x7FFA844B4517" | "0x7F14D3F7AFFC" | "0x7F7E083C6015" | "0x7F3A0AECA6CD" | "0x7F81571384A5" | "0x7F2D59BFAA14" | "0x7F3BF23040D7" | "0x7F2D04F383D2" | "0x7FF359E360EA" | "0x7FAA36BCA327" | "0x7F1EE7D51D68" | "0x7F4080AE355F" | "0x7F5941756455" | "0x7F1934AE4843" | "0x7F634CAFE53F" | "0x7FE2825D4D0B" | "0x7F627A785946" | "0x7FEADDA7B009" | "0x7F10A3BA6F23" | "0x7FCC385E07A2" | "0x7FBAAE5B1CF2" | "0x7FEB1BEDD7FE" | "0x7F4A232B5736" | "0x7F4498D7BFD7" | "0x7FFB79706D24" | "0x7F770B6B24FB" | "0x7F15D780632F" | "0x7FC1ECC6E650" | "0x7F0D2C937A95" | "0x7F055D6EA431" | "0x7F8C2F14AF9A" | "0x7FBB0A72B92B" | "0x7FD9B525018E" | "0x7FC617E892DF" | "0x7FB32240B22F" | "0x7FB20A32CBDD" | "0x7F9750E417A6" | "0x7FF037C1B1C8" | "0x7F78527F8A45" | "0x7F940B2384EF" | "0x7F1CCDF2C2D0" | "0x7F59FC7482B1" | "0x7F9BD696CDDB" | "0x7FFA40A015B2" | "0x7FA9FBF59A76" | "0x7F67C41ED933" | "0x7FFA738F93A2" | "0x7FA7B1FD939B" | "0x7F82530F6FF1" | "0x7FBCB294DBE9" | "0x7F5CF80BFA44" | "0x7F5299BA4E5E" | "0x7FEEDA03F455" | "0x7F0EE96BE3C4" | "0x7FE35E124062" | "0x7FAE5D5ED153" | "0x7F07B8C39FA3" | "0x7FF72F31A5A5" | "0x7F11F5F33FCC" | "0x7F05B9A42463" | "0x7FEE8795111C" | "0x7FA7F90CED32" | "0x7F44E814EE42" | "0x7F88E54AC08B" | "0x7F7768916277" | "0x7FD66B167F7F" | "0x7FDB2BB031AE" | "0x7FC52EDAF473" | "0x7F8CF5C2FBD5" | "0x7FCA98C7D5DB" | "0x7F20FDCCD1C9" | "0x7FC31FEA37ED" | "0x7F38D8A36201" | "0x7FDAA169E791" | "0x7F6ED37D0A0F" | "0x7FF2C0409074" | "0x7FB76D174785" | "0x7F677A48F9C0" | "0x7F2A74CA6846" | "0x7FB8A477811E" | "0x7F5CA1D3F1FA" | "0x7F68060BA4DD" | "0x7FA979A01869" | "0x7F635C19BFA0" | "0x7F265A5093D5" | "0x7F7BBB9D9EB6" | "0x7F81111B1A48" | "0x7F3FD66E13E3" | "0x7FEA3A9562B4" | "0x7FD18F29F191" | "0x7FC1AE07B2C9" | "0x7F7B406A4BA3" | "0x7F9988B505D4" | "0x7F78387A9EA6" | "0x7F6154895301" | "0x7FD7A4593B90" | "0x7F6F2A73672F" | "0x7F789CC9C9DD" | "0x7FADD4B14A7D" | "0x7FEA225DE8FB" | "0x7FB34B44BC00" | "0x7F374B602B29" | "0x7F7A3FA663E4" | "0x7F3E44E0BCE8" | "0x7F63C604BE30" | "0x7F0A7EE07F68" | "0x7F1A4FBEF561" | "0x7FFFD2A3BB09" | "0x7F7509BA24CF" | "0x7F1B88A7347C" | "0x7FE1509C0CBE" | "0x7F32CBB16822" | "0x7FFB3022AF9A" | "0x7F42CE1F8E48" | "0x7FE682E07AC0" | "0x7FA82CE88788" | "0x7F1895A16F0D" | "0x7F290A59F849" | "0x7FBA371EAEE9" | "0x7F665C098BE9" | "0x7F978F149A20" | "0x7F964DCDB588" | "0x7FF5E8BFA365" | "0x7FD3ABD11214" | "0x7FD34D5E7CC0" | "0x7FB87E31C150" | "0x7FA0BBC61769" | "0x7F080FF317A5" | "0x7F6903CB658B" | "0x7FE24071F3EF" | "0x7FE590EEB132" | "0x7FB291EF27D4" | "0x7FF1B9A4AB65" | "0x7FA460218AAE" | "0x7FB52EA2C789" | "0x7F925510EB0C" | "0x7FCE2CE07BA2" | "0x7F7E822EAF76" | "0x7F85A1B49FA7" | "0x7FDA76B65D21" | "0x7F48E13BA34B" | "0x7F0A583A09E0" | "0x7FA82AF8CE27" | "0x7F7AAF0C79D5" | "0x7FAB7C8F6A83" | "0x7F0A6CF38FC6" | "0x7F6E5BB97E0C" | "0x7F845F41614E" | "0x7FD0644D398E" | "0x7FA85642FA86" | "0x7F05F5D5C363" | "0x7FF6C6F80688" | "0x7F2E34951995" | "0x7F11F10058A7" | "0x7FBDA5C6FED1" | "0x7F7EB437B49E" | "0x7F3A0D2BCEB2" | "0x7F7DB6E70DA9" | "0x7FD3335B9238" | "0x7F6548E4C618" | "0x7FE49C57A18A" | "0x7F81AF78166B" | "0x7F087F4467E6" | "0x7F75AEE7CD0B" | "0x7F297CD459BB" | "0x7F4414332E38" | "0x7F58DDD206D9" | "0x7F4D218815A1" | "0x7FC45BDA4679" | "0x7F80BA8687D2" | "0x7FC1EC49E32C" | "0x7FC89911EF09" | "0x7F3AF141838A" | "0x7FFA0C18C177" | "0x7F8AA906C12B" | "0x7FFA22FFA861" | "0x7FFD5151A78B" | "0x7F9676C3E601" | "0x7F58374F63EF" | "0x7F88FBADC37A" | "0x7F8BC1423AC4" | "0x7F342BE38BDD" | "0x7F8DEA7E4879" | "0x7F6236FC3589" | "0x7FA7FD3EE359" | "0x7FFCFBF16A62" | "0x7FC9659F6982" | "0x7FA23D40BDDE" | "0x7F70F18ECA7B" | "0x7F875B317EA7" | "0x7F7C8DA9647F" | "0x7F5C542059A0" | "0x7F57D8B674A3" | "0x7F1FF96DE62D" | "0x7FBEEACA7927" | "0x7F566E59E7A4" | "0x7F0C17D5F522" | "0x7F9DFFA51457" | "0x7F3681C7330A" | "0x7FDC73D7B0AC" | "0x7F62FC42DF2C" | "0x7F096A642F1E" | "0x7F28576DF079" | "0x7F9C1AAF24A2" | "0x7FD390C0F795" | "0x7F23FD8241E2" | "0x7FDA30002586" | "0x7F8052446596" | "0x7FBBF6734F1E" | "0x7F613362663B" | "0x7F43BAF9D36A" | "0x7FCFCA3BE179" | "0x7FB3850C9FAF" | "0x7FAB87986CF5" | "0x7FE12F58715C" | "0x7FE341FDEF3F" | "0x7FDBDC30B386" | "0x7F14E4746D8A" | "0x7FC6C25AC665" | "0x7F09F6CBA381" | "0x7F53F7FA662E" | "0x7FE32FF7C0AF" | "0x7F6179163360" | "0x7F25A5D238C4" | "0x7FFE58FE567D" | "0x7F4F7EA293AA" | "0x7F1D3A26F402" | "0x7FCA303D8757" | "0x7FD3D2239156" | "0x7FDF6D906D5C" | "0x7F7BB75CEFDC" | "0x7FEF14EDE71A" | "0x7F46E54420C0" | "0x7FA74EE8F803" | "0x7F6BF7BF781C" | "0x7F9E1B5F7BC1" | "0x7FFDECE38EE2" | "0x7FC96714AF5C" | "0x7F3147F51608" | "0x7F638D64B034" | "0x7F9328FDE65C" | "0x7FE6ED3B4D83" | "0x7F3C7CCB8E66" | "0x7FA5A1A52F4E" | "0x7FFF0A321921" | "0x7F9702912D2C" | "0x7F3B8F9B840F" | "0x7F38201665AF" | "0x7F8315A1AE36" | "0x7FC3A734459C" | "0x7F9418DA1CFA" | "0x7F87276F3C6B" | "0x7F97FF7C2313" | "0x7FE7E05F4DBC" | "0x7F586CBB198C" | "0x7FE6904253D0" | "0x7F5ED6083613" | "0x7F962C2F12BB" | "0x7FE6A84EE308" | "0x7F9EBBEE289F" | "0x7F4E6DF7E684" | "0x7F05C971F0E5" | "0x7F53583453D5" | "0x7FDBCE92FC98" | "0x7F3EFBC77FD1" | "0x7FEE8AFD304F" | "0x7F41BD4F0893" | "0x7F3AA52BF5A0" | "0x7FA18F7B761F" | "0x7F663A38C556" | "0x7FC7F9AB56C3" | "0x7F4BC4DED467" | "0x7F228E1DF247" | "0x7FC5EFD38D87" | "0x7F294B999E18" | "0x7F79B56B7652" | "0x7FF707CC29B1" | "0x7FBDC02EB846" | "0x7FCA0B7A0203" | "0x7FD5DE1BF180" | "0x7FC769187954" | "0x7FB7AF4ED489" | "0x7F9E5160779E" | "0x7FB89D33F243" | "0x7F085EF9A5C2" | "0x7F98EE39B505" | "0x7F49AD4EEC00" | "0x7FF67367674C" | "0x7FD82EDA0957" | "0x7FC8FEAFBF71" | "0x7FDD7929EE0B" | "0x7F7DEF7DBA46" | "0x7F62A1513507" | "0x7F27877BD4BE" | "0x7FFAC9D2FBEE" | "0x7F74D2A79777" | "0x7F520B66CC75" | "0x7FFC807DEC66" | "0x7F2647F09AB7" | "0x7F460E2776AD" | "0x7FDB488A3F21" | "0x7F1237E483CD" | "0x7F8F4391CB34" | "0x7F4B626696F8" | "0x7F3686E39A60" | "0x7FD823F215E5" | "0x7F80C20286C9" | "0x7F0413190A86" | "0x7F499DBE5E33" | "0x7F54C06F3C04" | "0x7FD228A804BA" | "0x7F700FD18BEE" | "0x7F5B48F35574" | "0x7FBC1582D414" | "0x7F56CBE89874" | "0x7F1781B9E46D" | "0x7F671B3907BB" | "0x7FF89018B05C" | "0x7F070A230F7C" | "0x7F9A79E44D18" | "0x7F6916AD1405" | "0x7FBD77B985A3" | "0x7F9D30666141" | "0x7F35EAB2350B" | "0x7F16AA1BB773" | "0x7F95730A6907" | "0x7F8C0299225E" | "0x7F8049E48319" | "0x7F9A698827A4" | "0x7FB1AFF1E697" | "0x7FF5B9E31F7A" | "0x7FF99789F29B" | "0x7F637C9C2770" | "0x7F71A6821266" | "0x7F0F023714CC" | "0x7FBC0F675A47" | "0x7FDAF782996F" | "0x7FA2A491BBEA" | "0x7F23A88BE899" | "0x7F6717562A22" | "0x7F679C3C621C" | "0x7FC238B4EF89" | "0x7FB12EE94D59" | "0x7F2BD4C6DA3B" | "0x7F5293004D71" | "0x7FEE27F5844C" | "0x7FC06BEBC281" | "0x7F35834FD464" | "0x7F78E087A2AF" | "0x7F12E1197CF3" | "0x7FDD5C7B13DD" | "0x7F4D4CB6392E" | "0x7FA7EC161EAA" | "0x7F94F1213DAA" | "0x7FB8EFDB1757" | "0x7FEE55E4A53F" | "0x7F1D9E2DDC55" | "0x7FEBC3F17325" | "0x7F5E5EB9BF84" | "0x7FC606627E59" | "0x7FB4FAEDE021" | "0x7FDC415138D3" | "0x7FBA9CC85D51" | "0x7F7C2B620E04" | "0x7F1AF2807755" | "0x7FDB93DB4B49" | "0x7F44E1D29E82" | "0x7FE9325E8F2E" | "0x7FF441F20819" | "0x7F142FA4C45E" | "0x7F1B3802ACEE" | "0x7FFE1C78CE88" | "0x7FB31FE96DB5" | "0x7FC3BF81AF5D" | "0x7F2117431CD2" | "0x7F0986475CB3" | "0x7FB92DA8AC10" | "0x7FD7F9204050" | "0x7FFE8E163CAD" | "0x7F085EBE1600" | "0x7FE6F31DA4B0" | "0x7F40EFBD2320" | "0x7F580D416E34" | "0x7F9108EA943B" | "0x7F3203C355FD" | "0x7FC1B73772EC" | "0x7F198B7530DC" | "0x7F08825013EE" | "0x7FFADEDAD3E0" | "0x7F555534559D" | "0x7F0233D9D13C" | "0x7FC29B9BCBA5" | "0x7FD8526D988C" | "0x7F71C3F42024" | "0x7FAC0B077C09" | "0x7FE961F0FAD3" | "0x7FB753E10FE4" | "0x7F9D608FA1BA" | "0x7F92C6E18EA1" | "0x7F5DE97CD268" | "0x7F638BD03B7A" | "0x7F201A4FB3E9" | "0x7F5E23397E55" | "0x7F53766D1278" | "0x7F82E6F877C4" | "0x7FC1C553DE00" | "0x7FE4537B1EBC" | "0x7F7E26D23423" | "0x7FAD2577D213" | "0x7F8FEBC2E962" | "0x7F9464B58DBA" | "0x7F1D866F255C" | "0x7F389F980281" | "0x7FF7C54D925E" | "0x7FF7E75084BB" | "0x7F0CF7C85004" | "0x7F0CBEDC9613" | "0x7F9E1ED50144" | "0x7FC2B627689F" | "0x7FF23EB50C56" | "0x7FA9AC3B7234" | "0x7FF009307D2E" | "0x7FCEB1C1B4B8" | "0x7F701FCED4FC" | "0x7FF1873BFB9B" | "0x7F1B4CEBE3A5" | "0x7FA8DB6BD08B" | "0x7F89E15DBE0B" | "0x7F46D9843C0A" | "0x7F9D6977EB3B" | "0x7F8820961766" | "0x7F0A1C496D15" | "0x7F49BBDB5312" | "0x7FCF8085DD97" | "0x7F0CED243C9F" | "0x7F7F5CEBC1F3" | "0x7FF6C47E0C1A" | "0x7F5B388E8CDD" | "0x7F77DF2D76A4" | "0x7F594C28EDF3" | "0x7F5215B80730" | "0x7FD8AADD9C5D" | "0x7FDC067E54E5" | "0x7FAA5CF6B6FD" | "0x7FAC9F4CC459" | "0x7F25C8E587A1" | "0x7FE32C0A0F9E" | "0x7F6654158601" | "0x7FAC23A63E62" | "0x7F0CC76C372D" | "0x7F271DE852CF" | "0x7F90878FFF20" | "0x7FCFE57023C3" | "0x7F564927D0EF" | "0x7F0C87C30BE5" | "0x7F362F19EBB1" | "0x7FDD6E507C55" | "0x7F6B99BD2231" | "0x7F5B3E672FD1" | "0x7FAD2F472A6A" | "0x7F43C3BAA025" | "0x7FF6CA9A94A1" | "0x7F3ECA77DDD3" | "0x7F2124F8CA18" | "0x7FE955750ADB" | "0x7F8F85131C0E" | "0x7FF1A1A65B1B" | "0x7FDD3DFF1A4D" | "0x7F1A58BFD894" | "0x7F1C1FB65C77" | "0x7FF8E0CAA477" | "0x7F5A699579DA" | "0x7F378597DDA8" | "0x7F49DE1EBEF3" | "0x7FE4BB925DB6" | "0x7F78B646F716" | "0x7FA7F69175E7" | "0x7FEB0D419B62" | "0x7F644BA98CDB" | "0x7FBFBAD56EB0" | "0x7F60184B94BB" | "0x7F4CC1D0C342" | "0x7F19D620241D" | "0x7FAFDDC1F920" | "0x7FD8596B3049" | "0x7F92808CC983" | "0x7F65AF43B9BA" | "0x7F5547A0A9CD" | "0x7FD2EDFACBFC" | "0x7F181EB0975F" | "0x7FAA594E272C" | "0x7FE42BD284C9" | "0x7F4D5A6B52FD" | "0x7F9C28D7E90E" | "0x7F1F7DCB63FC" | "0x7F8A8F1536A6" | "0x7F614EE44FF9" | "0x7FDB7D3A1E00" | "0x7FC125F1FB44" | "0x7FE2D7F80BE7" | "0x7F374216939A" | "0x7F8DD2122521" | "0x7FF32C877058" | "0x7FD51896ED8E" | "0x7F350370996F" | "0x7F37398C82EA" | "0x7F6C25F17107" | "0x7FB90D0080BF" | "0x7F7659A1B02B" | "0x7FC711011AFD" | "0x7F0E43691AB9" | "0x7F596E75A1D2" | "0x7F36857BD5B3" | "0x7FBA5B887559" | "0x7F6545393CFC" | "0x7F1A502D2239" | "0x7FE69B69B9BA" | "0x7FAC5A35EB27" | "0x7F6E16F890E8" | "0x7F1E5FFE798C" | "0x7FC5C8375997" | "0x7FF3AFAA54CA" | "0x7F89047A71D3" | "0x7F1268F2299E" | "0x7FCBEFB6F24D" | "0x7FB0F4A3F818" | "0x7F81EE3C64F6" | "0x7F2FA56DA17C" | "0x7F776316570C" | "0x7FBADB033644" | "0x7F5AC2AD3C6D" | "0x7F25E0C985EB" | "0x7FB36562E12F" | "0x7F493A5F6354" | "0x7F04CE49C10E" | "0x7F9E9B0F33F8" | "0x7FD600A33BB3" | "0x7FA6A8181D1D" | "0x7F4528F3B47B" | "0x7FA1F60247B7" | "0x7F82633C52CE" | "0x7FB87278D774" | "0x7F4EF89DC76F" | "0x7FE0BD2A50F7" | "0x7F91EEFDA9F4" | "0x7FA3EA0486EB" | "0x7FF806A9E8E1" | "0x7F44122C4806" | "0x7FFD60A1D382" | "0x7F462EFC0E09" | "0x7F10C1767F8B" | "0x7FE69AAF65BE" | "0x7FE20697BB9B" | "0x7F5B529B4EE5" | "0x7FDA26B82A70" | "0x7FB2C54D0383" | "0x7FD8D5F139E5" | "0x7FDBB32C0E07" | "0x7F6D2C3459E5" | "0x7FDBBABB449F" | "0x7FDE011ECC80" | "0x7F757DA2C43B" | "0x7F8C7D86F7EB" | "0x7FC9CA26D346" | "0x7FADB2E8F46C" | "0x7F0367C30E39" | "0x7FF28B9DDE50" | "0x7F488206617B" | "0x7FCE5C95558C" | "0x7FDC496EF502" | "0x7FDE39DAF966" | "0x7FD9042D68F4" | "0x7F1912DBC920" | "0x7F97F58FDE9F" | "0x7F6722A9897B" | "0x7FD945D7F980" | "0x7F5AAE3B3991" | "0x7F4E9072543E" | "0x7F61F024CC02" | "0x7FD51C360226" | "0x7FD8535ED1AE" | "0x7F5A2596358C" | "0x7F4C36EC8CFC" | "0x7F2E0ACC30AA" | "0x7F6EC6823270" | "0x7FE9CEB71F58" | "0x7F62FCB293D2" | "0x7F504E383C53" | "0x7FB371D46FED" | "0x7F313C077C9C" | "0x7FE0AEB41492" | "0x7FDE6E2ADCC9" | "0x7F99CC81B2E8" | "0x7FA73D6E2AD6" | "0x7F646C4E188D" | "0x7FB5AD420EC6" | "0x7FF3F6238B49" | "0x7F34E72610F6" | "0x7FCAFB18F5E9" | "0x7FF5CFF300F1" | "0x7FD51314D0A2" | "0x7F3400569E9F" | "0x7F4AB288E1BD" | "0x7F4934D4CD91" | "0x7F75D050BE31" | "0x7F7B4D88E45E" | "0x7FC0A1341671" | "0x7F8BE0B8FFD5" | "0x7FCAD1200666" | "0x7FE2F3C71750" | "0x7F528295BD79" | "0x7F5118F103AD" | "0x7FF4F6550F9E" | "0x7FA7808FABF3" | "0x7F5CA9D54A48" | "0x7F3D15346A96" | "0x7F614A0CBA3A" | "0x7F1A69009467" | "0x7FDB93FEFC87" | "0x7F0C2C70CB74" | "0x7F57F8FAB90E" | "0x7F60F2224519" | "0x7F14B3F7C6C5" | "0x7FF9BCE653C5" | "0x7F7AD5E12970" | "0x7FDD52C21A99" | "0x7FFA11F66E10" | "0x7FA7B99AB48D" | "0x7F2BAEDFF749" | "0x7F9102C02E10" | "0x7F1A3CCD4EF3" | "0x7FA1DEF7A5FD" | "0x7F75C82C11D2" | "0x7FCD9E04616F" | "0x7F76CF91BADB" | "0x7FB856A4A17A" | "0x7FF0F189943E" | "0x7F96B8C4C154" | "0x7F4B1D058CB7" | "0x7FF68A2833C3" | "0x7F8D45BCBBF4" | "0x7FB06C66D5E0" | "0x7FB55B90C608" | "0x7F7D538AC1F9" | "0x7FC49B0922CD" | "0x7FAA90096621" | "0x7FF5F710077F" | "0x7F4ADC36C9F8" | "0x7F81F8F31416" | "0x7F586A857FA0" | "0x7F37BF3E7EE5" | "0x7F11CC1095D1" | "0x7F2B8F3F16FA" | "0x7FAB0A0C2791" | "0x7FE0B61D8256" | "0x7F31BDE6FD3D" | "0x7F4772707D39" | "0x7FC4589B3467" | "0x7FC0EFF5E2BE" | "0x7F214D8F97E9" | "0x7F1310C31B99" | "0x7FC0DC2BF2A6" | "0x7FBF9EEEFB12" | "0x7F6254488AAC" | "0x7FFE5C437581" | "0x7F8A21282D4E" | "0x7F5D241EE332" | "0x7F11289F36CC" | "0x7F601661D626" | "0x7F077D79F588" | "0x7F8397C5DD10" | "0x7F8CFDAF0CE5" | "0x7F78D4EC886D" | "0x7FAB5350E224" | "0x7FCC0F818CDD" | "0x7FAF45422C38" | "0x7FA1C7E38766" | "0x7F867027253E" | "0x7F73251DFBDE" | "0x7F845A8A8EE1" | "0x7F711F010D9A" | "0x7F0EE496CE18" | "0x7FDA5E0A15D9" | "0x7FD6DBCC1F90" | "0x7F59C4D35C78" | "0x7F24C1C72AFA" | "0x7FDA75156EA2" | "0x7F27917BBC45" | "0x7FB208548673" | "0x7F3B0F68BD6E" | "0x7FB366BA7952" | "0x7F0B2AE19C08" | "0x7F8882CA470A" | "0x7FC1C22B6077" | "0x7F62EA71AA95" | "0x7F3120C58EDA" | "0x7F67C83E4BCF" | "0x7F5AADF532B0" | "0x7F830841E8CE" | "0x7FC29439614A" | "0x7F68E4EAD7A6" | "0x7FA11811D206" | "0x7F499B350074" | "0x7F6D19C4ACDE" | "0x7F510F5C7038" | "0x7FEB49D1A212" | "0x7F9F9B394C0F" | "0x7FB32E975311" | "0x7FB410F99D62" | "0x7F4C76EFBDD7" | "0x7F2733688160" | "0x7F393C88B020" | "0x7F3471CEAF07" | "0x7F2C70CC433B" | "0x7FA777021057" | "0x7FD88FF9D2CE" | "0x7F674305DAE6" | "0x7FF27DC31DC3" | "0x7FA4492F6544" | "0x7FB0625D7104" | "0x7F40FB12FA10" | "0x7F527960F97A" | "0x7F35447D550A" | "0x7F7AE210ED46" | "0x7F750F1562B8" | "0x7FED51546399" | "0x7FCC3149748E" | "0x7FB3A4C46890" | "0x7F6618D349EC" | "0x7FD70469019B" | "0x7FBB14E1BB80" | "0x7F14C28F2DE8" | "0x7FF3F0BE6992" | "0x7FE4A08916D3" | "0x7F21465ED6B5" | "0x7FFCF85DD33D" | "0x7F7DE953EC01" | "0x7F685D990500" | "0x7F40631B9C10" | "0x7FA1D5C9BC91" | "0x7F25B858E50D" | "0x7FE8B922E5CF" | "0x7F1091D518FE" | "0x7FFDBDAD7DBC" | "0x7F6C0046736E" | "0x7FC509AF61EE" | "0x7F6987AE9ADB" | "0x7F91D237E0AC" | "0x7F55B8C1E9F6" | "0x7F09575ACCF8" | "0x7FB3E00D7CFD" | "0x7FE396DDEE00" | "0x7F18117D9A58" | "0x7F9C061BBC5F" | "0x7FAA0722FC8D" | "0x7F372C581CD9" | "0x7FD218AEE6C6" | "0x7F74B2969520" | "0x7F5D2EBCC81B" | "0x7F5B70853159" | "0x7FD0ACA1CF5F" | "0x7F176544C4D1" | "0x7F2CBCE3FDFF" | "0x7FA2584A2446" | "0x7F7BA74AD036" | "0x7F4216B4723F" | "0x7F51ADE408AA" | "0x7F60185E3B1B" | "0x7F61C09F5AE7" | "0x7F0F4DDD0BAD" | "0x7F77D9FF9B76" | "0x7F1572AEA011" | "0x7F220F9340B0" | "0x7F281F6F5FA6" | "0x7F1A1346FA04" | "0x7F3239701915" | "0x7FFD0E6CB4CC" | "0x7F17DD23CDC1" | "0x7FA04B358012" | "0x7FBC018DDF43" | "0x7F4595067AA4" | "0x7F369C78DFB5" | "0x7FC76483E7DF" | "0x7FB9015F4FB5" | "0x7F5690EBC862" | "0x7FCE7E3300C2" | "0x7FDCD5926FF2" | "0x7FC48FA4D8E2" | "0x7FC535B6507F" | "0x7FD4FA079987" | "0x7F67DFF432DB" | "0x7F6446E22BE9" | "0x7FC89F203B2E" | "0x7F84A18CDDB6" | "0x7F25FC956F5C" | "0x7FE48340D719" | "0x7F480E3928FE" | "0x7FAD2F91EBC2" | "0x7F57FB002645" | "0x7F2E18F2856D" | "0x7FD73B639820" | "0x7F392071F36E" | "0x7FAC16E08047" | "0x7FD96DA19406" | "0x7FAEF0829B4A" | "0x7F1ECFE39EDB" | "0x7FCE293FA468" | "0x7FAD745CC9FB" | "0x7FD1B66435BE" | "0x7F9E16E2115F" | "0x7F640A1E1D92" | "0x7FCD1A154703" | "0x7FEFB5D79184" | "0x7FAB70997184" | "0x7FA44ED36B3E" | "0x7F08E0503D43" | "0x7FBF3ACA2C43" | "0x7F6626EFE89E" | "0x7F227C8B86A3" | "0x7FF0ABEC1562" | "0x7FC787380D4A" | "0x7F3613830239" | "0x7FAF58257940" | "0x7FC7E80FD47A" | "0x7FFE4E00994B" | "0x7FFCDBBC7611" | "0x7F977BCF5796" | "0x7F9C37C38C05" | "0x7F1D851E3325" | "0x7F07AAA61D2D" | "0x7FCA7FD8E1E8" | "0x7F3AF70C7D98" | "0x7F5CD327C508" | "0x7FC9F216387E" | "0x7F8906C32329" | "0x7F6D9D141B41" | "0x7F22F4B14C9D" | "0x7F82ED277163" | "0x7F84F439F6BA" | "0x7FE71C5BEEC7" | "0x7FD7557E12B2" | "0x7FC6E43DAB0E" | "0x7FB2C04E6DDB" | "0x7F0F1B05913B" | "0x7F3B8B94A0A4" | "0x7FA9F14B6EFD" | "0x7F11524F048C" | "0x7FA49F7B7FFD" | "0x7F6D2FCD78BF" | "0x7FBDB5049E84" | "0x7F5ACB539B76" | "0x7FEF57158354" | "0x7FD0C2E628B7" | "0x7FD1AE91172E" | "0x7F99B3D5AB2D" | "0x7F4200E6C3FB" | "0x7F475CBD7F08" | "0x7FFC10B097AB" | "0x7F2A1AD979CD" | "0x7F8D727897D1" | "0x7FFCD947E700" | "0x7F38DE203FD5" | "0x7FA46650CC11" | "0x7F579152FDF9" | "0x7F95CF74139F" | "0x7FBD1C3AC2B5" | "0x7F7B156A9FB5" | "0x7F4E52E18F0D" | "0x7F12449E3953" | "0x7F8B81653114" | "0x7FECFE1A3FD5" | "0x7F2368AB1F28" | "0x7FFC51A320DA" | "0x7F9CF4B2728E" | "0x7FC0404A2952" | "0x7F80CC8DB1B1" | "0x7F461A17E0F4" | "0x7FE2307E136D" | "0x7F009915063A" | "0x7F19134C952D" | "0x7FCAC5ABAB84" | "0x7F8EE049FD90" | "0x7F01B3966519" | "0x7FCD1000814B" | "0x7F30F60FF530" | "0x7F912377281C" | "0x7FC8171CD118" | "0x7FAE05352A26" | "0x7F3B21708FCA" | "0x7F3442C876E6" | "0x7F5662B3A40B" | "0x7F82AC83F2D9" | "0x7F6BB0F5862F" | "0x7FD660F473DB" | "0x7FAA02B190B0" | "0x7F14A0B2F1A7" | "0x7FC3CE8E0D25" | "0x7FAD81214561" | "0x7F9CACE30542" | "0x7FB8653E4C9E" | "0x7FD9E8A6E8C0" | "0x7FEAB9F5E8F8" | "0x7F9CF9F677EB" | "0x7FA03648EF4B" | "0x7F7287EB9D8A" | "0x7FC889B41AA8" | "0x7FE9FA62F70D" | "0x7FB226FE5AEA" | "0x7F63BE4487E2" | "0x7FAD404E65A0" | "0x7F7A549A9E9B" | "0x7FA960F6FF70" | "0x7F0CB810C606" | "0x7F45C42982DD" | "0x7F206D0BD760" | "0x7FB3CCE31140" | "0x7F2D36B35837" | "0x7FFD35F7E25E" | "0x7F6B0BC99DFC" | "0x7F690DC138D1" | "0x7F55E4F42E41" | "0x7FEC06275B20" | "0x7FF915E6C4C4" | "0x7FF20E05DCF3" | "0x7F8F283824CB" | "0x7F6242465906" | "0x7FF9C909B02D" | "0x7F8FF366BA86" | "0x7F36A3698738" | "0x7F59C091C88A" | "0x7F252AB06F6D" | "0x7FE776DDF79B" | "0x7F6CC0E2D984" | "0x7F83A9EE4725" | "0x7F5347A99DB4" | "0x7F7047CA49BA" | "0x7F53B0C7B734" | "0x7F21EDA93EB6" | "0x7FF2EFD03857" | "0x7FBE0062BA1B" | "0x7F8D03142166" | "0x7F9A1E6DEDB7" | "0x7FDF5C939948" | "0x7F199C25A09D" | "0x7F5B0BFDC425" | "0x7F2EFBD80B1B" | "0x7FC3A0E58F66" | "0x7FF07D2B6364" | "0x7F0D2F55F866" | "0x7F2C82024AED" | "0x7F2D4099C71C" | "0x7F2C06326845" | "0x7F86F553BCCE" | "0x7F39029034C8" | "0x7F2A3BCC3748" | "0x7F8425A2DA7A" | "0x7F0D21079F73" | "0x7F944ACD2602" | "0x7FF1EC5E9B4D" | "0x7F41782D8ADD" | "0x7F17A4914E6C" | "0x7FA3E34C9FD0" | "0x7FC3FCD0D260" | "0x7F51DBC50C35" | "0x7F8D9676A873" | "0x7F6F0D17BF7A" | "0x7F5A7AE50FB1" | "0x7F624BA25A53" | "0x7F7A9F4CED3F" | "0x7FAD09246EAE" | "0x7F11F5E1A63C" | "0x7F5F418B49CE" | "0x7F72A219A7AB" | "0x7FF2864A0E4A" | "0x7FBF3460B36A" | "0x7F8D02278FC9" | "0x7F594FA2CBEA" | "0x7FEF447AA210" | "0x7FFD72DC9931" | "0x7FA3A63348FB" | "0x7F5CBDBEBD64" | "0x7F07C08A9243" | "0x7FB6DB5C126D" | "0x7F0006F1A9E6" | "0x7FFA5EFFB5C5" | "0x7F25E207AC2E" | "0x7F6B2FDE56A7" | "0x7F3628A7783D" | "0x7F720A8A6665" | "0x7FACB2A77043" | "0x7FF186B72F11" | "0x7F34A69DFB30" | "0x7FD80B71EE73" | "0x7FEF4185B540" | "0x7FA4279C561D" | "0x7F0205EA2006" | "0x7F79B95818AB" | "0x7F3DFB402CC7" | "0x7FF0C08BC0CB" | "0x7FD87D60BA44" | "0x7F3C2845ED55" | "0x7FAEECBE1B56" | "0x7F33DF7E230A" | "0x7F28B75DC4C9" | "0x7F487CFCCAB4" | "0x7F708A37EB71" | "0x7FEA234025E5" | "0x7FD9501FE284" | "0x7FEA78278BF6" | "0x7FB866B64E68" | "0x7F1C664ADFD0" | "0x7F34B0A6216D" | "0x7F7AEBB98881" | "0x7FC4D05384A9" | "0x7FAD6632BCC5" | "0x7F2EBBD07B7D" | "0x7F85F3FAC9AA" | "0x7FD54E92E424" | "0x7FCCDB83CB7D" | "0x7F25C89BE0A3" | "0x7FCF9FC7459B" | "0x7FD334553D5B" | "0x7FA3DBE459AB" | "0x7FF366C82258" | "0x7F7A4F8098BE" | "0x7F1B4D99B6E9" | "0x7F9B6AA77985" | "0x7F155CC278A9" | "0x7F1D483F2AEA" | "0x7F88A873BA61" | "0x7F798B6E9954" | "0x7F24A07A9619" | "0x7F4CFFEEDD2E" | "0x7F86D4AC921B" | "0x7F67E3E253B7" | "0x7F23263D1823" | "0x7F6EE0F05AB2" | "0x7F67BF8F412C" | "0x7F64591EE0F6" | "0x7FC02FC70446" | "0x7FCFEBFDEED7" | "0x7F8B078888F3" | "0x7F541ACBD3AD" | "0x7FDA7A623829" | "0x7FF587CBAE93" | "0x7F8ACBEB156A" | "0x7F2BB8B186E9" | "0x7FAD2EF15A55" | "0x7FEE76A9372E" | "0x7F935877F1D6" | "0x7F02220F5835" | "0x7F3A97D77AEB" | "0x7FA874BA2993" | "0x7FDA176C78B6" | "0x7F5D8F51BF40" | "0x7F988EC2C138" | "0x7F3149122D68" | "0x7F4760FFE6A4" | "0x7F69CCC662E9" | "0x7FC6F3261936" | "0x7FF78219E80A" | "0x7F0BF12DF3F0" | "0x7FD09D2A92A3" | "0x7FDC5885F9B6" | "0x7FF105B66686" | "0x7FA5C335CA9C" | "0x7F8653070CCA" | "0x7FA7D6690BA7" | "0x7F7A54A12011" | "0x7FE9CC93E23E" | "0x7F3A3BB7A01F" | "0x7F059021E039" | "0x7FED756F97C6" | "0x7F8439373A3B" | "0x7FC950229D43" | "0x7FB23D50C6BD" | "0x7F4F701B20D5" | "0x7F7971D387C4" | "0x7FB184C9E9EA" | "0x7FEC0BD5CC34" | "0x7F5928C4CECC" | "0x7F7F154958C6" | "0x7F8BCCE0659F" | "0x7F335DCF2D71" | "0x7FD500A7C8FA" | "0x7FE3EED70FC3" | "0x7F7F7C018040" | "0x7F78B7D2A048" | "0x7FDA762C02C5" | "0x7FBE87621C08" | "0x7FAA00CEFAF9" | "0x7FF3E489BC88" | "0x7F7FAEE58D4B" | "0x7F39E9F0C336" | "0x7F5B7A97CD14" | "0x7F458DEE0483" | "0x7FDFD777FFD0" | "0x7F56A47E648D" | "0x7FCD6FEBA545" | "0x7F8F28388A3B" | "0x7F4E4A57D68B" | "0x7F354DA50EBE" | "0x7F83672CD4E3" | "0x7FDF61CB42EF" | "0x7F00E3AEB527" | "0x7F057E138F20" | "0x7F3B6C0A7F9D" | "0x7F46CFF22190" | "0x7F168B0A81B0" | "0x7F9FC2FCF12E" | "0x7F0D9A9D122D" | "0x7FB3C5BF2B68" | "0x7F0033498734" | "0x7F77ECD823AA" | "0x7FF3ED71DFAD" | "0x7F772F794837" | "0x7F54ECE79C9D" | "0x7F9B4F890DA9" | "0x7FCADE05A7C1" | "0x7FBAFADFE246" | "0x7F7398503DEC" | "0x7F4E9EA1AC15" | "0x7F4375293E63" | "0x7F1BBAF4285B" | "0x7F373CE9BA6D" | "0x7F70F48FA530" | "0x7FA17B728D62" | "0x7FABF11EF99C" | "0x7F12724867CC" | "0x7FF2A9E52DFC" | "0x7FB82007ECF9" | "0x7F858ABC7304" | "0x7FA9F42CE450" | "0x7FA2EB5BF751" | "0x7FE3E17C08FD" | "0x7F65EEA1DEEB" | "0x7F5D7CD5EFC9" | "0x7F39E3EC753A" | "0x7FFFE49A9544" | "0x7F11257B7E60" | "0x7F35559C6B31" | "0x7F925B477BD3" | "0x7FB63F196BEB" | "0x7FC89367DBE5" | "0x7F73F6BD8021" | "0x7F2134B4B4BE" | "0x7F67A47E58B8" | "0x7FE8450C11B5" | "0x7FBB27A5C21D" | "0x7F3C3C389911" | "0x7F564EFF9B21" | "0x7FDE082BF7B6" | "0x7F3DD601B554" | "0x7FCEA0244788" | "0x7F6410714DAA" | "0x7F071A93028D" | "0x7F69FE453E65" | "0x7F41BC35C379" | "0x7F0D8B1661DD" | "0x7F57C4CB6110" | "0x7F250ABA764C" | "0x7FEF2C5A9934" | "0x7F817490F756" | "0x7F27A361791A" | "0x7F54C334C0B1" | "0x7F6DD424EBB7" | "0x7F0A77F1ED32" | "0x7F1EA420ADE3" | "0x7F1A89ABE56B" | "0x7FC05A233158" | "0x7F4C8270FE19" | "0x7FEC93E2E44C" | "0x7FE4ACA582FA" | "0x7F9E58F9562B" | "0x7FBBD7DEAA6C" | "0x7F87C9F69057" | "0x7FB9AA7DF1A7" | "0x7F31BFFF6055" | "0x7F6B1BA116DB" | "0x7FF1C3A6A14A" | "0x7F6E77D60C40" | "0x7F6257BBE7BA" | "0x7F8227ED3558" | "0x7F64A5A165D0" | "0x7F22A2240E80" | "0x7FCCAE6149CE" | "0x7F1145C03E80" | "0x7F864F90C972" | "0x7F06DEE776FD" | "0x7FACBDFEF68F" | "0x7FC4ACFD0842" | "0x7FAE567BE892" | "0x7FE9BC165F1C" | "0x7F1242112537" | "0x7F9B42F59D3B" | "0x7F0667D17887" | "0x7FC036C3AFF1" | "0x7F56F2602844" | "0x7F3296932EA5" | "0x7F6BEB6D4247" | "0x7F5F302AA1E6" | "0x7F34DA98258C" | "0x7F09EB5E1A42" | "0x7FF15C26C355" | "0x7FC559B75CB3" | "0x7F282D09F6ED" | "0x7F7B57A56C4A" | "0x7F2860CC3EE5" | "0x7F35178FFDA5" | "0x7FB72D9EA0D8" | "0x7F8FB56010BD" | "0x7F813127449C" | "0x7FE4C8922475" | "0x7F513BC5769D" | "0x7F2567737125" | "0x7F7225F9AE16" | "0x7F0638FBCC21" | "0x7FEE78BE9211" | "0x7FDD911EE740" | "0x7F83E5F34E4E" | "0x7FDE47CF3560" | "0x7FD3828CC692" | "0x7FC9B8FF0C42" | "0x7FC5083B2437" | "0x7F6F6F4B00FC" | "0x7F09DBDCFED4" | "0x7FDA25C344EA" | "0x7FFACF869E1A" | "0x7FEFBF8CC8D9" | "0x7F2105D2E699" | "0x7F6EAE176276" | "0x7F2380861988" | "0x7F16D83BB618" | "0x7F2ED97B26D4" | "0x7F2CB31F8223" | "0x7F732D337DF1" | "0x7FBBA472C9A7" | "0x7FAD13556551" | "0x7FCC88753436" | "0x7F68F6014128" | "0x7F41D0D4E78C" | "0x7FE96DC7230D" | "0x7F23AE8851D8" | "0x7FC4D9C85FCE" | "0x7F1CB592BF09" | "0x7F1B16630E71" | "0x7F451AF8C179" | "0x7FDEABA0C98C" | "0x7FE37B7C7D81" | "0x7F3BFAB82B23" | "0x7F0B9EB6BCCB" | "0x7FC2EAB615D6" | "0x7F4C3AECBB28" | "0x7FBB9278BF47" | "0x7FD0618AE252" | "0x7F06B714E006" | "0x7F11027D2E59" | "0x7FA5F9F8F85F" | "0x7F6B5D569DF9" | "0x7FB3B10D19D9" | "0x7F1D14C9A722" | "0x7F7640B73D8B" | "0x7FBF397FB51A" | "0x7FACAE945452" | "0x7FCE04653091" | "0x7F21671ECD57" | "0x7FAC68172CC0" | "0x7FFBE9BA18D2" | "0x7FE1FCFCF941" | "0x7F8A39A6CB16" | "0x7FBA16886A4F" | "0x7F13352871A8" | "0x7F2B717254BE" | "0x7F6A2424FEDB" | "0x7FFE5C306B3A" | "0x7F58379D8F62" | "0x7FC2F9F3B506" | "0x7F1AC566E60E" | "0x7F2D8AE64DFE" | "0x7F64803B28AD" | "0x7FECBC97E7A2" | "0x7FC35C8283FD" | "0x7F5BDEF6BDB8" | "0x7F808A8289D5" | "0x7F60C4BD335D" | "0x7F1BBB62C62A" | "0x7F9F69A08B0F" | "0x7FDF228B3861" | "0x7F67C18A9A93" | "0x7FAE7AB278A5" | "0x7F3E9F876FB6" | "0x7FAF85EA5E36" | "0x7F4D7E5C8157" | "0x7F3B5A4DCC1B" | "0x7FCE6B29FF00" | "0x7F2F018A6C42" | "0x7F9FEA8A7A54" | "0x7F3B540CB1E0" | "0x7FE2A6264645" | "0x7FAFB5977377" | "0x7F8ED480ECDD" | "0x7F847EB734AC" | "0x7FAF5A173E45" | "0x7FCC8C388756" | "0x7FA299A7A9E4" | "0x7FBE7FFDFFB1" | "0x7F6434BFF7ED" | "0x7F05240C8847" | "0x7FDFF72590B0" | "0x7FC61D846BBC" | "0x7F7600FEB536" | "0x7F86E04CF29A" | "0x7F079845C5DF" | "0x7F6F4290F2E3" | "0x7F675449BF0C" | "0x7FD63C8BD530" | "0x7FC719E0B2C4" | "0x7F7EAC63E347" | "0x7F4B6A146FF3" | "0x7F793D13A437" | "0x7F944ED649C7" | "0x7FE30C7AEC01" | "0x7F20ABA39A1D" | "0x7FE438286353" | "0x7FD5ED64BEF6" | "0x7F3A41BC397D" | "0x7F11E5FA6132" | "0x7F2BE9DC3D84" | "0x7F4373A0B048" | "0x7FDE36366516" | "0x7F6CD36798E7" | "0x7F7F8BDD9432" | "0x7F3A75D46393" | "0x7FEF4DA5B10B" | "0x7FDE54398133" | "0x7FCA64E16BA7" | "0x7F1CE13A6E7D" | "0x7F227350FF9A" | "0x7F5215D24866" | "0x7F78EFDEB239" | "0x7F9A4BF827CD" | "0x7FA73D556CAC" | "0x7FACAFAC6BBC" | "0x7F1C12204070" | "0x7F249BEA2322" | "0x7F6C21998BDF" | "0x7FC2E7810A20" | "0x7F5EBDFA8EC5" | "0x7F379FDF557D" | "0x7F51822A80A7" | "0x7F147B40B8D2" | "0x7F33AF4814C3" | "0x7FE627547FF6" | "0x7F3BDB801641" | "0x7FADDE06522B" | "0x7F430A777079" | "0x7F4642939443" | "0x7FCDF45909C4" | "0x7FE94F93EE25" | "0x7F925112B837" | "0x7FA72B2FDA57" | "0x7F13F15D6001" | "0x7FC58CC7834F" | "0x7F1958ADCD60" | "0x7F51E53620A4" | "0x7FBE23FF2D7D" | "0x7FA150E58211" | "0x7F364CCC5045" | "0x7F0C0F4DA246" | "0x7F8BE6399291" | "0x7F959835FEB8" | "0x7F90CFA4229C" | "0x7FF526AFD99E" | "0x7F7DEAF87C5C" | "0x7F62B0A53966" | "0x7FB31EDB1897" | "0x7F4C9F431C0B" | "0x7FE868076378" | "0x7FADD8D7AEE8" | "0x7F0EC7F6D202" | "0x7FF3EC0BEE25" | "0x7F7C1BE86BAC" | "0x7FAF86F78932" | "0x7FA882EDBAF4" | "0x7F7302F3D792" | "0x7F0A95723D2D" | "0x7FFC03E6E9D0" | "0x7FCD07464366" | "0x7F83A818574F" | "0x7F57DBDAD95D" | "0x7F78CF8130BC" | "0x7F46BBBC61C4" | "0x7F4E455B35D0" | "0x7FB800A07ACB" | "0x7F8B2DA05095" | "0x7FBCB6CC0415" | "0x7FAB4CBF796C" | "0x7F95FFF11978" | "0x7FD1EB420618" | "0x7F5E6CD45D16" | "0x7F057107D746" | "0x7F0455719E30" | "0x7F2BB3B867D9" | "0x7F2B0335A3A6" | "0x7FF22584888F" | "0x7F1AF8153951" | "0x7FA3003131A4" | "0x7FB571EE02EA" | "0x7FEEC012157E" | "0x7FE47C11E387" | "0x7FF5EFE94DFD" | "0x7F2104467F25" | "0x7F76B0D310FB" | "0x7F749F43C3B5" | "0x7F525EB66A82" | "0x7F5EC9F1E697" | "0x7F03F39A5733" | "0x7F143B820BC6" | "0x7FB1EE824E00" | "0x7F4D9E15F80B" | "0x7F8AAE21CA3C" | "0x7F3DF58D9D38" | "0x7F2D61040436" | "0x7F629D7337D3" | "0x7FF3B2EC87B8" | "0x7F2251EEFC60" | "0x7F26BD7BCFC6" | "0x7F4242D4DDA8" | "0x7F1A025E2603" | "0x7FF7BA508159" | "0x7F1ECAE8A7C7" | "0x7F7BA668CE5A" | "0x7F70DAA9226C" | "0x7F9C6F0F0CAA" | "0x7F66A157694A" | "0x7FF670776CA4" | "0x7F890EDEB5D3" | "0x7F6F77A71777" | "0x7F4CB8500BD4" | "0x7F19A070E08D" | "0x7F541340E5E4" | "0x7F0F295CD41F" | "0x7FCECED61742" | "0x7FD3122A0C0C" | "0x7F0FB5BA6B2C" | "0x7F3CA24D30EC" | "0x7FA8617B4147" | "0x7FF3116B99B4" | "0x7F0D688B944F" | "0x7F6C6315B2C4" | "0x7F77FE7FF4DC" | "0x7FE1F19F1A64" | "0x7FD5633DAA3F" | "0x7F94653C9BC5" | "0x7F851800BF8B" | "0x7FF4EDBEA77A" | "0x7F07F2D70018" | "0x7FC074C47C4C" | "0x7F4C7B59C005" | "0x7F13D15E684D" | "0x7F6B50ED103D" | "0x7F2EF246234C" | "0x7F810D987D09" | "0x7F4085B78DB7" | "0x7F598B754998" | "0x7F7BBDDF11E5" | "0x7F984021AF8A" | "0x7F4D85572D08" | "0x7FA8C5B1CE3F" | "0x7FE1E85144EE" | "0x7F9D57CFA66F" | "0x7FA648CEBA7A" | "0x7F0E7CDFD524" | "0x7F5905CD1913" | "0x7F311CE770B6" | "0x7F0F18660A71" | "0x7FFC1A77EF85" | "0x7F8161B8A065" | "0x7FC4E4A1C2AC" | "0x7F2D7EE79A84" | "0x7F4982B94210" | "0x7F7DE9856822" | "0x7FF096ED9148" | "0x7F9FCB927ABB" | "0x7F1F19362B08" | "0x7FE5B1D90D3E" | "0x7FAD8545B123" | "0x7FD5C519D230" | "0x7F5DE24105FC" | "0x7F37F564D9AC" | "0x7FA9F98F1A16" | "0x7F813D1B810E" | "0x7FCD379B36EE" | "0x7F4EE8CC5440" | "0x7F7D957DC81C" | "0x7FE94EFB388B" | "0x7F18416B6B45" | "0x7FE1FF9F6C02" | "0x7F7BDA15FC6F" | "0x7F87D7275036" | "0x7F0F85669FAA" | "0x7FB280259939" | "0x7FBCB2A8B2D6" | "0x7FDAA4068DB8" | "0x7FE30762DD29" | "0x7F481351AA9D" | "0x7FF0B6B1ECC9" | "0x7FDC877406F2" | "0x7FE6F591C6BF" | "0x7FA3119E7D1F" | "0x7F6AD413E445" | "0x7FDCEA843148" | "0x7FC8519536F3" | "0x7F3A3BDED3DE" | "0x7F3E5E6F255C" | "0x7FF76ED867FC" | "0x7F9B2AC1A363" | "0x7FDE3CC0999E" | "0x7FA50E88CCE9" | "0x7FEEC97766BC" | "0x7FB4BE2FD86E" | "0x7F9F113D185F" | "0x7F8AF4373B6D" | "0x7F7935AF6A7D" | "0x7F30A420A4F7" | "0x7F944E6D1058" | "0x7FF7B1AEB30E" | "0x7F78BAFA50AF" | "0x7F9FA7F0119A" | "0x7FCCE16A89B9" | "0x7F913B9B693C" | "0x7FE95ABFF6F2" | "0x7F19823F525E" | "0x7FA2B2ECBA49" | "0x7FC44542B34A" | "0x7F0BA7F63474" | "0x7FAD51115219" | "0x7F1FE5BD152D" | "0x7F2CF96C85F9" | "0x7FBA1F7E2528" | "0x7F70DC19E989" | "0x7FFE89AA3479" | "0x7FF8930EE523" | "0x7F73F2988E85" | "0x7F45823F15DE" | "0x7F5287046B2C" | "0x7F9F7B73CF80" | "0x7F2C704AB970" | "0x7FAF9CF2CA7D" | "0x7F54BE5A17DE" | "0x7F1D627C5C38" | "0x7F6DA7D83750" | "0x7F5C8AF73A4F" | "0x7F5D72640286" | "0x7FC3740683C5" | "0x7F2983F57CD1" | "0x7F3C859323CD" | "0x7F5F80F4DB7E" | "0x7F39D45A6167" | "0x7FB3D9A7C307" | "0x7F754070E797" | "0x7F61CF43DB4F" | "0x7FDD0AB8C693" | "0x7F401190FA9B" | "0x7F6E2523750F" | "0x7FB523647E15" | "0x7F34768595F6" | "0x7FC8A442EB47" | "0x7FDA80364C5C" | "0x7F357BE17FEC" | "0x7F28047A1A23" | "0x7F9A7D98A18F" | "0x7F2529FEF130" | "0x7F553F987223" | "0x7F5586655415" | "0x7F466808AB79" | "0x7F42A85DA36E" | "0x7FC7F99CF21D" | "0x7F20C4F1C29B" | "0x7F238734E9F1" | "0x7F213B2C1E9F" | "0x7F01D5359877" | "0x7FCBDACD6567" | "0x7FE68C6E5089" | "0x7F34BF92A912" | "0x7F47F3518F1C" | "0x7FAF038D05C2" | "0x7FEEFF6C71E2" | "0x7FE851350D7F" | "0x7FCF35B13DCE" | "0x7F405B41A92C" | "0x7F06A39E522D" | "0x7F05F5E34EC4" | "0x7F7F8C5EF46D" | "0x7FC86534298C" | "0x7F2BC27EACC6" | "0x7F9904EEFA06" | "0x7F46C476B45B" | "0x7FCF43649AF3" | "0x7F037D4FFA07" | "0x7F370F4B6BBA" | "0x7FB7CADA580D" | "0x7FD01C328487" | "0x7F5350467817" | "0x7FB97D9701D6" | "0x7F16CCEF4EEB" | "0x7FC0B7460773" | "0x7FBC85483FF4" | "0x7F23B8EEAE52" | "0x7F3289F7CA40" | "0x7FE9338CC81B" | "0x7F0280B132CF" | "0x7F4DD02BC42A" | "0x7F90C72F8894" | "0x7FBB97D99241" | "0x7F39C10D208F" | "0x7F4F73227B3E" | "0x7FB01030338D" | "0x7FEF8C22B48F" | "0x7F085AB3C371" | "0x7F095B39E608" | "0x7F60B968E0AD" | "0x7F70801AC366" | "0x7FF1ABB7B3F4" | "0x7FA0BA7A2AC4" | "0x7F1881C49490" | "0x7FFBF1A1CE4D" | "0x7F4C3F3B9CD9" | "0x7F0D3051F3FA" | "0x7FF3B41159FC" | "0x7FB845B210D6" | "0x7FAB15E8BD04" | "0x7FE5A408D51D" | "0x7FBBF8FDB1F3" | "0x7FF7D0FFC4D7" | "0x7F463313785C" | "0x7FA6BF51E153" | "0x7F1F2448A78B" | "0x7F06542FBCE2" | "0x7F1F0D9B70D7" | "0x7FED74714F16" | "0x7FDEA44AD341" | "0x7F5A8480B80F" | "0x7F3E4E5DF2A1" | "0x7FC1171A59D9" | "0x7F7684C93BF2" | "0x7FEF0C83ED00" | "0x7FE1B44EDF45" | "0x7F79E1997116" | "0x7FAC4AD8A897" | "0x7FB4FC339CF9" | "0x7FB009E5205A" | "0x7F21B7727C8D" | "0x7FF6EA4ACABD" | "0x7FF1884E4B9E" | "0x7F259A872B13" | "0x7F7878004E9F" | "0x7FCEB748D9D9" | "0x7F9D55396F2E" | "0x7F6ADC020FAD" | "0x7F2947CAC1A9" | "0x7F7504D02A3F" | "0x7F2CE299BBB5" | "0x7FE2FCC4816A" | "0x7F3BC5B54F33" | "0x7F180ED503A0" | "0x7F809E5D6BEA" | "0x7FAFA80B90B1" | "0x7F4D0EA6BC90" | "0x7F313E71EF0C" | "0x7F6FA551E499" | "0x7F9840B9CFDC" | "0x7F1DC3F823C1" | "0x7F08B8B48494" | "0x7F96B33B163E" | "0x7FB8E84057CB" | "0x7F65A477D4CB" | "0x7FF51C3B2E6E" | "0x7FDA3C85D5B6" | "0x7F3C5F082A4C" | "0x7F18DFDBF667" | "0x7FDB45ACBA36" | "0x7F3D9BBAC08E" | "0x7FFAEAE66923" | "0x7F0ACBD4F4AB" | "0x7FAB4AE70A43" | "0x7FCC2D7F7500" | "0x7F1214AB7653" | "0x7F8A0E4B69C5" | "0x7FD8524027F0" | "0x7FAFFC77D9EC" | "0x7F1574D45FEE" | "0x7FA17139E4E5" | "0x7FDC8C1F23E3" | "0x7F0061FCDFFB" | "0x7FCFC6DAA710" | "0x7FC0B285096D" | "0x7F810EBBD48D" | "0x7F37BAC9AE6E" | "0x7FF1E83E4D9E" | "0x7F6DF0737FAF" | "0x7F6B9EEA69E2" | "0x7F9E9850918B" | "0x7F5AEB7F9765" | "0x7F9A5EEAECB8" | "0x7FD8DE7D16A4" | "0x7FE8C588FC7F" | "0x7F5EA764C800" | "0x7F23466BDAF2" | "0x7FC1D2C211CD" | "0x7F9AE32CA340" | "0x7F84A11FF317" | "0x7FBE57433EEE" | "0x7F2EE037EF8D" | "0x7FA3D0BD7EBA" | "0x7F20A02677C9" | "0x7F3587CB4A99" | "0x7FBAD43DA41C" | "0x7F61E78BA4D6" | "0x7F138006213F" | "0x7F8E6EF40C45" | "0x7F65FC96D5CC" | "0x7F63CFE5B888" | "0x7F8BBEA805C8" | "0x7F9F9F471B76" | "0x7FBA69AB34EE" | "0x7FA59997ABBB" | "0x7F2E584EA83B" | "0x7F862CAA6F9F" | "0x7FF3EEE03D70" | "0x7F1160E981AB" | "0x7FE8C68FEAFC" | "0x7FD6537EBC53" | "0x7F7697F225F6" | "0x7F7FC201E28B" | "0x7F0CD013AE0A" | "0x7FF421DDA2BD" | "0x7F36C0A0F222" | "0x7F4021E835C4" | "0x7F1054766077" | "0x7F99DCF9FAE0" | "0x7F79ED263F06" | "0x7F05D7FBD2B3" | "0x7FAA9FDD541E" | "0x7F7B5E16F1CB" | "0x7FFF48EC97C1" | "0x7F91EF5EF677" | "0x7FB2D7994FC1" | "0x7F1185345E4B" | "0x7F59051922FC" | "0x7F1E84F61A3A" | "0x7F11CAF7B96D" | "0x7F216B52A1AF" | "0x7F6C2E2AB973" | "0x7F9BF3BB1350" | "0x7F662148A672" | "0x7F88186F10AC" | "0x7F6590AA3AA1" | "0x7F983AB9810C" | "0x7FE3F60BADD5" | "0x7F55473691B4" | "0x7F91583A4B39" | "0x7FB09ABA34F8" | "0x7FA17B306E31" | "0x7FA924778ED9" | "0x7F798E70E795" | "0x7FE6F65853E9" | "0x7F88FAA1E0CA" | "0x7F6BE722D413" | "0x7F98B36DA277" | "0x7FE2A51764EE" | "0x7F8D88895DF4" | "0x7FA431601962" | "0x7FCC13C66F9C" | "0x7F6F70336FC1" | "0x7FC8B621CC64" | "0x7F75C82069BB" | "0x7F3DA38C242C" | "0x7F3279792E0C" | "0x7FFC1F49A1D0" | "0x7FE15D6064B9" | "0x7F98CDD16473" | "0x7FD6C185DD2A" | "0x7F8FF86269E3" | "0x7F745AC8B784" | "0x7F929881F29A" | "0x7F98F491AFD4" | "0x7F9AE7020180" | "0x7F092685C8D8" | "0x7FC6837930F5" | "0x7FC73CAB0539" | "0x7F5FE4823D38" | "0x7FD9507B03D7" | "0x7F6FE8445C85" | "0x7F200F8F31B9" | "0x7FBB479DFF0C" | "0x7F7EB4EE4D37" | "0x7FFEBBB4D414" | "0x7FC1DAC7FD6E" | "0x7F7CAAC59268" | "0x7F66087F8EFB" | "0x7FABBE02B742" | "0x7FEE5983A101" | "0x7F0432AD304C" | "0x7FFDDD5883A7" | "0x7F9A5E2EFCF2" | "0x7F647B8AC7C5" | "0x7F2C4DDA790B" | "0x7FE259A72568" | "0x7FF27084F5AB" | "0x7FB1C1FA5718" | "0x7FADAED2300B" | "0x7FF0479D80A6" | "0x7FCE755CD662" | "0x7F843A991F17" | "0x7F8068197F31" | "0x7F3F2045D4EC" | "0x7F448F881E41" | "0x7F9630D74929" | "0x7F4C14A0B6AF" | "0x7FFFA71EE83F" | "0x7FDE7D471AA3" | "0x7FC9C52AF712" | "0x7F965D11BC51" | "0x7F99B6C2F972" | "0x7FF8D68F33DF" | "0x7FD5B6AD3827" | "0x7F4BA2E8A16F" | "0x7F78F15D854C" | "0x7FABB26D6BE8" | "0x7F81EB31098E" | "0x7F9DDC490014" | "0x7FE9C0995AFF" | "0x7F4BA9A689D0" | "0x7F384F284ECE" | "0x7F2AA1081EFD" | "0x7F2FF01302C0" | "0x7F6664B6B18C" | "0x7FDD66B590A9" | "0x7F0D96E29E00" | "0x7FA97D489A42" | "0x7F561D16FD2F" | "0x7FA040D588E4" | "0x7FA28845DC5E" | "0x7F25DB029EAA" | "0x7F4F13D528C4" | "0x7F10D3D50154" | "0x7FABFA258D2B" | "0x7F928FD284B1" | "0x7F326D9095F6" | "0x7F653FF970A0" | "0x7F63C3649B9D" | "0x7F69394A5EBF" | "0x7F578D5E5AB3" | "0x7F82178505EC" | "0x7F871E4BDB27" | "0x7F9A204982ED" | "0x7FC9A8E34CCE" | "0x7F01D0F3972C" | "0x7F401F476657" | "0x7F42297D6635" | "0x7FF038B326B7" | "0x7F0F5B95A489" | "0x7FF1B0CBD7C3" | "0x7FB1E9B815CB" | "0x7FF86C0C24E5" | "0x7F3074478D03" | "0x7FEDCC1BD9A8" | "0x7FA22F08ADCF" | "0x7F527E5703CE" | "0x7FF8829E5E4B" | "0x7F440FE89DBE" | "0x7FAD63715B5F" | "0x7FCA13D66321" | "0x7FDE9A973DC6" | "0x7F6F3DD1F497" | "0x7F815357FBA1" | "0x7FD8AF8622FC" | "0x7F1097ED5073" | "0x7F6B58A7D9A1" | "0x7F13BBE0597B" | "0x7F720B95ECAE" | "0x7FF0B7EF29A8" | "0x7F9C77F7FB7A" | "0x7F433041C31D" | "0x7FBE95F16030" | "0x7FC0FA20E6F6" | "0x7F43DB296BAD" | "0x7F63FB821A09" | "0x7F63637DF100" | "0x7F55520656A9" | "0x7F4136717752" | "0x7F79999503FC" | "0x7FAA90A7C641" | "0x7F56A65C1229" | "0x7FC4B455BA6F" | "0x7FAA44FFD221" | "0x7F9524A5DC51" | "0x7F36FD4BEE21" | "0x7FCC9E4DBD83" | "0x7F2DC21D043C" | "0x7FA5229454B4" | "0x7FEC973CFB62" | "0x7FE974F5A60D" | "0x7FB50BFA3566" | "0x7F80D17439DD" | "0x7F5064BE53BA" | "0x7FEFED7B5A5B" | "0x7FC4DF8C6477" | "0x7FBE1F619697" | "0x7FE296FE897B" | "0x7FB682BF6A87" | "0x7F43EA690592" | "0x7F4DEE494397" | "0x7FFCC2B2B15D" | "0x7F96F2967EAF" | "0x7F3B696A0D59" | "0x7F98B69366B4" | "0x7FC2D0A65109" | "0x7F11F8007464" | "0x7FD349A84A77" | "0x7FF5F91853F4" | "0x7F6019E6D4B2" | "0x7FE105C4DD6F" | "0x7FA11BCC5873" | "0x7F7FF2ADD218" | "0x7F64D194074E" | "0x7F39AC4C8B8C" | "0x7FC9E0DBE024" | "0x7FF0905E1422" | "0x7F3308DDB847" | "0x7F69BA057852" | "0x7F690E0DBEA3" | "0x7F4278D09C3C" | "0x7F92DF62D423" | "0x7F2ABBA5642F" | "0x7FD001246D70" | "0x7FB13580B81B" | "0x7F61BCBA20A9" | "0x7F7E6F00D39B" | "0x7FA9DF767E4E" | "0x7F029DD69198" | "0x7FF98DAAC499" | "0x7FCE7256232C" | "0x7FF0C72AC6E1" | "0x7F422DCBFC3D" | "0x7FD61C744519" | "0x7F77F63DC43A" | "0x7FB3B213EC88" | "0x7F949858EF7A" | "0x7FE8D11DA10E" | "0x7F979C9F1BD5" | "0x7F0532C52973" | "0x7FBA021FDA3C" | "0x7FF6E8590BA8" | "0x7F5894AEE81A" | "0x7FD52D1000FC" | "0x7F26B11B930E" | "0x7FBB492A363B" | "0x7F80524DA3AB" | "0x7F2357329E21" | "0x7FE589100185" | "0x7F7A6B7A0A4C" | "0x7FD640795B52" | "0x7F6605BB2831" | "0x7FD8591C3722" | "0x7F4012D02AB0" | "0x7F1B11E173AA" | "0x7F56F1DFDA95" | "0x7F06B2C7A899" | "0x7FBD871B0DE4" | "0x7F52578BC4E9" | "0x7F248EAC0633" | "0x7FC226826B87" | "0x7F8386F89DA6" | "0x7F7C9D83D80E" | "0x7F382493AD72" | "0x7FF11A9D1165" | "0x7FE8C96E6354" | "0x7F26C51B91C3" | "0x7F921C453A4F" | "0x7F7308E64769" | "0x7F07D51C3715" | "0x7F36085CEB66" | "0x7FDA55BAC65C" | "0x7F58ACE62FDC" => {
            if body.advisoryIDs.iter().any(|advisory_id| !is_expected_advisory_id(advisory_id)) {
                return Err(AttestationVerificationError::AttestationError(body.isvEnclaveQuoteStatus));
            }
        }
        #[cfg(feature = "insecure")]
        "GROUP_OUT_OF_DATE" | "CONFIGURATION_NEEDED" => {}
        "SIGRL_VERSION_MISMATCH" => {
            return Err(AttestationVerificationError::StaleRevocationList);
        }
        _ => {
            return Err(AttestationVerificationError::AttestationError(body.isvEnclaveQuoteStatus));
        }
    }

    let quote = SgxQuote::decode(&mut &body.isvEnclaveQuoteBody[..]).map_err(AttestationVerificationError::InvalidQuote)?;

    if &quote.report_data.0[0..32] != expected_report_data {
        return Err(AttestationVerificationError::InvalidQuoteReportData);
    }

    let our_report = sgx::create_report_raw(None, &[0; 64]).map_err(AttestationVerificationError::CreateReportError)?;
    if quote.mrenclave != our_report.body.mr_enclave.m {
        return Err(AttestationVerificationError::InvalidMrenclave(quote.mrenclave));
    }

    if quote.is_debug_quote() {
        #[cfg(not(feature = "insecure"))]
        {
            return Err(AttestationVerificationError::IsDebugQuote);
        }
    }

    let unix_timestamp_seconds = parse_ias_timestamp(&body.timestamp)?;
    let certificate = (ias_report.certificates.get(0).ok_or(webpki::Error::BadDER))
        .and_then(|certificate: &Vec<u8>| webpki::EndEntityCert::from(certificate))
        .map_err(AttestationVerificationError::InvalidCertificate)?;
    let chain = (ias_report.certificates.get(1..).unwrap_or_default().iter())
        .map(|cert: &Vec<u8>| &cert[..])
        .collect::<Vec<_>>();
    certificate
        .verify_is_valid_tls_server_cert(
            IAS_CHAIN_ALGOS,
            IAS_TRUST_ANCHORS,
            &chain,
            webpki::Time::from_seconds_since_unix_epoch(unix_timestamp_seconds),
        )
        .map_err(AttestationVerificationError::InvalidCertificate)?;
    certificate
        .verify_signature(&webpki::RSA_PKCS1_2048_8192_SHA256, &ias_report.body, &ias_report.signature)
        .map_err(AttestationVerificationError::InvalidSignature)?;
    Ok(AttestationParameters { unix_timestamp_seconds })
}

fn is_expected_advisory_id(advisory_id: &String) -> bool {
    match advisory_id.as_str() {
         "0x7F7A5663985B" | "0x7F4B5436F5EA" | "0x7F612DD8C611" | "0x7F0B2E694DDA" | "0x7F522E875E7A" | "0x7FF08F3C763B" | "0x7F6B57F9E591" | "0x7FFB03602CB0" | "0x7FA5E9649493" | "0x7F7385DD7236" | "0x7FDDEE501447" | "0x7F224C7CCD8A" | "0x7F97A779F94D" | "0x7FBC90D543A5" | "0x7F767C4DCF61" | "0x7F7AB27DCB04" | "0x7F63C211EE69" | "0x7FEFD54F7268" | "0x7F82A7C6A559" | "0x7F2E2B5142E0" | "0x7FD2B4CE599B" | "0x7FFBB4D1D66F" | "0x7F18DD272493" | "0x7FCBD51AA8EA" | "0x7FECF650BB0C" | "0x7FC6A7A80EDC" | "0x7FF4C354F285" | "0x7F283A7501D5" | "0x7F69E9D9744E" | "0x7F9E4DB40C66" | "0x7FF91678FB20" | "0x7F6B2E335A0F" | "0x7FF9B3A7D3FF" | "0x7FB0D2E93417" | "0x7FF9743D9875" | "0x7FEA76182758" | "0x7F069103AB3F" | "0x7FAC4514C5FE" | "0x7F7863DE20EA" | "0x7F6F95511A0C" | "0x7F8B96886B7D" | "0x7FA0C14EB9DE" | "0x7FED304D5698" | "0x7F92FD404C93" | "0x7F788E731DC0" | "0x7FBA5578A585" | "0x7F3A0A589716" | "0x7F09B0150426" | "0x7F1BD69CA26E" | "0x7F660D0397F1" | "0x7FA074746B30" | "0x7FD4065F72B2" | "0x7FABE2E8DD43" | "0x7F9C339BBDD1" | "0x7FA9B9F02112" | "0x7F164D874B8A" | "0x7F0D838A4CB7" | "0x7FFB05A88C39" | "0x7FF2E2DBEB03" | "0x7FC8D07356BA" | "0x7F8008BEB93E" | "0x7F8A03E97013" | "0x7F98BA41DB82" | "0x7F5FE0AF2580" | "0x7FBE08A5BF23" | "0x7F58E3D3F2F8" | "0x7F3C45CFEABB" | "0x7F6F81CCB528" | "0x7F693DF3230F" | "0x7FACA8DDAB27" | "0x7F1F999524DA" | "0x7FEC779C0353" | "0x7F8894093DBF" | "0x7F9E48CF6A19" | "0x7FDBBD082DA6" | "0x7FE1299AC28F" | "0x7FA73052072B" | "0x7F3153F584BB" | "0x7FDD424DEA48" | "0x7FC4C149FF10" | "0x7FEC0E65B78B" | "0x7FA3953E744F" | "0x7F863186F4EC" | "0x7F954D6D4A7D" | "0x7FF58636F487" | "0x7FC5D71D87E3" | "0x7F1EC99E9E86" | "0x7FB739F8AF1F" | "0x7F65B03C848E" | "0x7FCDF34E8E72" | "0x7F61940BEF4B" | "0x7FFA1C9B04E4" | "0x7F2CDEB41CDA" | "0x7F124D2DB194" | "0x7FDE599D1680" | "0x7FE63F2D1C9C" | "0x7F043EF90E4E" | "0x7F589B570FDE" | "0x7FB2C91C217B" | "0x7FE9F61852A3" | "0x7F7D695E2C3E" | "0x7F9EFB79D23E" | "0x7FFD610D8C9A" | "0x7F8042318BF1" | "0x7FEA95B8475D" | "0x7FAE49B94576" | "0x7F8917D7A301" | "0x7F14B5987B56" | "0x7F5FCA0B4BB4" | "0x7F87D10CDDFC" | "0x7F5C22B19F9F" | "0x7F5A8B05DB25" | "0x7F9F8FD0E2A7" | "0x7F2F144CE155" | "0x7F48FCDF8F32" | "0x7F072A67F86C" | "0x7FC037FBA32C" | "0x7F3F34BD6D8B" | "0x7FE9B0306B22" | "0x7FA293FDFF49" | "0x7FF39B4F397E" | "0x7FC1B723FDFE" | "0x7F37D6ABE728" | "0x7FA812F6547B" | "0x7F3A06F232BE" | "0x7F6D284FDDAB" | "0x7F3ECD41D5DE" | "0x7F5DEA4D8B37" | "INTEL-SA-00289" | "0x7F104264D083" | "0x7F2D71418120" | "0x7FC8B72F98F9" | "0x7F3F83CE0F44" | "0x7FBE04F2EDDD" | "0x7F241CD873BF" | "0x7FE4ADF4626A" | "0x7F080FB68CAD" | "0x7FBAC7722F3E" | "0x7F9AB6D6FCA3" | "0x7F0AB3B6FE73" | "0x7FFBD4D6E7CC" | "0x7F00FA2311D9" | "0x7F10DEB2A0AE" | "0x7F8FC6895F10" | "0x7FDA85D34CC0" | "0x7F9043F189AA" | "0x7F9330106977" | "0x7F1AED484587" | "0x7FAFF16C29F3" | "0x7F2859271209" | "0x7F5BE2199606" | "0x7F6964C4ABA7" | "0x7FD13FAAE10D" | "0x7F8B2D0C8B25" | "0x7FC15804499E" | "0x7FF7D59BBEA6" | "0x7FE53325A225" | "0x7F3A5B99BD83" | "0x7FE393DAE6A7" | "0x7F8905A45C1B" | "0x7F78385F7258" | "0x7FF321B66DD5" | "0x7F5EBB8CF838" | "0x7F70E16D190D" | "0x7F2D198F48BE" | "0x7F3D47B08ED2" | "0x7FFB54403F4F" | "0x7FE2024DED81" | "0x7FDD0A628BB3" | "0x7F2D8994A7D9" | "0x7F5D945AC94F" | "0x7F8E1AE1C5B2" | "0x7FE0B84B7739" | "0x7FE41FDFE276" | "0x7F306A7E42A1" | "0x7F7CF098B963" | "0x7F00750D5B4A" | "INTEL-SA-00219" | "0x7FD2179D6302" | "0x7F1926E9AA6F" | "0x7FEB104F031F" | "0x7FE83B02AB5C" | "0x7FAC3E4E76BD" | "0x7F45A31D9F8F" | "0x7F9EFA57BF70" | "0x7F9739372D7D" | "0x7FC2A084400B" | "0x7F89F822A233" | "0x7F1FA118692D" | "INTEL-SA-00615" | "0x7F36B72E9166" | "0x7FB7411EAA97" | "0x7F25E6AC3A6B" | "0x7F7A764D0345" | "0x7F4AE744713C" | "0x7F3D673B7DB1" | "0x7F631CA43C98" | "0x7FFBFEE8D78D" | "0x7F2267B67C88" | "0x7F2A10FE064B" | "0x7F1A4086A8DE" | "0x7F4DD5ADEEC7" | "0x7FF1A6CA774C" | "0x7F5DCBEFCD21" | "0x7F7F8A8220B1" | "0x7F3C0507E467" | "0x7F3DAC3A3A8B" | "0x7F1537B75E9F" | "0x7F30609299CE" | "0x7F3EA9C675FD" | "0x7F83C64270D8" | "INTEL-SA-00334" | "0x7F31370156F6" | "0x7FE088F0321E" | "0x7FEFE57AE7B9" | "0x7F9619624AD2" | "0x7F1510C4A798" | "0x7F92D5F0CF3F" | "0x7F321CD60177" | "0x7F93689CDAC2" | "0x7F7C682B7D90" | "0x7F1E57AF14DA" | "0x7F27B0F5E392" | "0x7FA71473F2C8" | "0x7F388C4FB8E6" | "0x7FE12EA7C1FB" | "0x7FF340040E85" | "0x7F7D75C9FB38" | "0x7FE96CA735EB" | "0x7F90E84ED467" | "0x7F5021F62F8D" | "0x7F6830E7E75B" | "INTEL-SA-00161" | "0x7F89648862F9" | "0x7F19D3F9E571" | "0x7F94758FB38C" | "0x7FE00C8702FF" | "0x7FD241110F32" | "0x7FD7E5AE0BB6" | "0x7FA7F09B4736" | "0x7F1A30F45A31" | "0x7FE318C8B737" | "0x7F3254C9C97A" | "0x7FBA9A77A4AA" | "0x7F660FCB2020" | "0x7F6DE5ECFD00" | "0x7F6AF58213C5" | "0x7F7EDE85C6B4" | "0x7F781AD4C16A" | "0x7F2A4EAAFE89" | "0x7FADFF76FED5" | "0x7F95615A8D02" | "0x7FC638FD9F09" | "0x7FDF042933A9" | "0x7F99C7E90302" | "0x7F83CE872C1F" | "0x7FF1C17E23CD" | "0x7FED56398827" | "0x7F7461C61DE7" | "0x7F738411A35F" | "0x7F85D0F5D0FA" | "0x7FCEC9F9EC3A" | "0x7F2C04992014" | "0x7F00008AFCD7" | "0x7F24E65CE784" | "0x7F28CDBB49CA" | "0x7FC1C33B2B32" | "0x7F3926A3B737" | "0x7F4A2185E819" | "0x7F8CF9B184DB" | "0x7FFB0F293D1E" | "0x7F42D7097A89" | "0x7F80EECCB67D" | "0x7F382724A01C" | "0x7F2B6BDE66D5" | "0x7FB04871F89C" | "0x7F2F1B1BE343" | "0x7F37F899A84A" | "0x7F56942A1EC9" | "0x7F9CCA71CCCB" | "0x7FBF717387CA" | "0x7F504BB58A91" | "0x7F5BA0A5A600" | "0x7F6C2E3E5757" | "0x7FB11F21C833" | "0x7FDFA4572DC9" | "0x7F26B19B9383" | "0x7FBBD64D8257" | "0x7F5E190343B3" | "0x7F291F608328" | "0x7F5D6CB5AE8D" | "0x7FAFFB62E207" | "0x7F48A6D4A0A3" | "0x7F1F6BD6344E" | "0x7F1E28CEFB49" | "0x7FBEBD835F05" | "0x7FAE843C68CE" | "0x7F234A1C1DFE" | "0x7FF33C91457D" | "0x7F9797260559" | "0x7F11F2D7B80E" | "0x7F977947E191" | "0x7F66DB2160CE" | "0x7FFF7C45DBC5" | "0x7FF1CD39FC74" | "0x7FD2BBDAF71D" | "0x7FF608BD72BD" | "0x7F7217493FF2" | "0x7F329E57AEE0" | "0x7F4747C828E1" | "0x7F468D6F93BE" | "0x7F61E7F689C3" | "0x7F951720BF38" | "0x7FDD8AE9AB2A" | "0x7FED55CE51AD" | "0x7FAB8F315DC9" | "0x7FBF78117BC2" | "0x7FC97FE0804F" | "0x7F8098961118" | "0x7FB7FF577579" | "0x7FDBD9DF309F" | "0x7FCEF1241B49" | "0x7FF7150565CB" | "0x7F92410E4105" | "0x7F7DEBC7C795" | "0x7F63681C01F9" | "0x7FC558E8CA56" | "0x7FF821272A58" | "0x7FE2E67F679C" | "0x7F72E82CDFDC" | "0x7F7F63E01248" | "0x7F87A8986C46" | "0x7FC1F173829D" | "0x7F329742EA25" | "0x7FB53127DA84" | "0x7F4124B43C40" | "0x7FA1BE45C9A2" | "0x7FD46DCB1380" | "0x7F206AFE774C" | "0x7F4E66BD45FD" | "0x7F1A8D574215" | "0x7F12FB8F7B3D" | "0x7F5B6D293D3D" | "0x7F9991EFF585" | "0x7F95569D480C" | "0x7F5F83870EE8" | "0x7FFB02777D5D" | "0x7F8FA1BE68EB" | "0x7F8E105EBD15" | "0x7F23439E7DBD" | "0x7FE69520F009" | "0x7FE248BF2110" | "0x7FC4CCE2E6D5" | "0x7F4E408A4E99" | "0x7F55FB20F100" | "0x7FFD954E49B7" | "0x7FF56346C502" | "0x7F9162095C23" | "0x7F680C75E9B4" | "0x7F3747C90113" | "0x7F99CAE67D02" | "0x7F2AF3D11B71" | "0x7FC03B8FCC90" | "0x7FE700FE49F9" | "0x7F253DCB7953" | "0x7F6442CC7887" | "0x7FB4FBFD6332" | "0x7F83571359AD" | "0x7F31BF23FC62" | "0x7F4722745FB1" | "0x7F23A04F74C4" | "0x7FBB7A29DFBB" | "0x7F038AAE3722" | "0x7F0734D64F1D" | "0x7FC4987C7A4D" | "0x7FDA0E0E66E5" | "0x7F2F5A493815" | "0x7F9DEB1A1E96" | "0x7F6708E28170" | "0x7FA732A560AB" | "0x7FC4628EEF2C" | "0x7F5C6ACF0246" | "0x7F02C96B1D84" | "0x7F445C02ECEE" | "0x7FDCC4BC2714" | "0x7F6395010FF7" | "0x7FF1A32E90F8" | "0x7F744490D9A1" | "0x7FBF44EEC9A7" | "0x7F7AB95F15BB" | "0x7F5DB83166B0" | "0x7FBCF626EFEB" | "0x7FBF9032CAEC" | "0x7F67E20A02CA" | "0x7F38B194DB67" | "0x7F557BB6EF2A" | "0x7F331F2C3FEC" | "0x7F6E097D4DB4" | "0x7F7D6467EA0B" | "0x7FD5846F2EEE" | "0x7F618C5B4EB2" | "0x7F7523FDA3BD" | "0x7F1F05A681F2" | "0x7F312DEC9C92" | "0x7FDDA87FFAA9" => true,
        _ => false
    }
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
pub struct IasReportBody {
    pub isvEnclaveQuoteStatus: String,

    #[serde(deserialize_with = "deserialize_base64")]
    pub isvEnclaveQuoteBody: Vec<u8>,

    pub version: u64,

    pub timestamp: String,

    pub advisoryIDs: Vec<String>,
}

impl fmt::Display for AttestationVerificationError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, fmt)
    }
}

//
// NodeId impls
//

impl<T: AsRef<[u8]>> From<T> for NodeId {
    fn from(from: T) -> Self {
        let from = from.as_ref();
        if from.len() == NODE_ID_LEN {
            let mut id = [0; NODE_ID_LEN];
            id.copy_from_slice(from);
            NodeId::Valid(id)
        } else {
            NodeId::Invalid(from.to_vec())
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&util::ToHex(self), fmt)
    }
}
impl fmt::Debug for NodeId {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

impl Deref for NodeId {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            NodeId::Valid(id) => id,
            NodeId::Invalid(id) => id,
        }
    }
}

//
// NodeParams impls
//

impl NodeParams {
    pub fn generate(node_type: NodeType) -> Self {
        let params = NOISE_PARAMS.parse().unwrap_or_else(|_| unreachable!());
        let builder = snow::Builder::with_resolver(params, Box::new(SnowResolver));
        let keypair = builder.generate_keypair().unwrap_or_else(|_| unreachable!());
        assert_eq!(keypair.public.len(), 32);
        Self {
            node_key: keypair.private.into(),
            node_id: keypair.public.into(),
            node_type,
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

//
// NodeType impls
//

impl fmt::Display for NodeType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::None => write!(fmt, "none"),
            NodeType::Replica => write!(fmt, "replica"),
            NodeType::Frontend => write!(fmt, "frontend"),
        }
    }
}

//
// HandshakeHash impls
//

impl HandshakeHash {
    fn get_hash_for_node(&self, node_id: &NodeId) -> [u8; 32] {
        let mut hasher = SHA256Context::default();
        let mut output = [0u8; 32];
        hasher.update(&self.hash);
        hasher.update(node_id);
        hasher.result(&mut output);
        output
    }
}

//
// AttestationParameters impls
//

impl AttestationParameters {
    pub fn new(unix_timestamp: Duration) -> Self {
        Self {
            unix_timestamp_seconds: unix_timestamp.as_secs(),
        }
    }
}

//
// Shared impls
//

impl<M> Shared<M>
where M: prost::Message + 'static
{
    fn attestation(&self) -> Option<AttestationParameters> {
        match &self.session {
            SessionState::Authorized { attestation, .. } => *attestation,
            _ => None,
        }
    }

    pub fn send(&mut self, msg: impl Borrow<M>) -> Result<(), ()> {
        match &mut self.session {
            SessionState::Authorized { noise, .. } => {
                let mut encoded_msg_data = SecretValue::new(Vec::with_capacity(msg.borrow().encoded_len()));
                assert!(msg.borrow().encode(encoded_msg_data.get_mut()).is_ok());
                match write_noise_message(noise, &self.noise_buffer, encoded_msg_data.get()) {
                    Ok(encrypted_msg_data) => {
                        #[allow(unused_assignments, unused_mut)]
                        let mut debug_msg = None;
                        #[cfg(feature = "insecure")]
                        #[cfg(feature = "trace")]
                        {
                            debug_msg = Some(format!("{:?}", msg.borrow()).into());
                        }
                        kbupd_send(EnclaveMessage {
                            inner: Some(EnclaveMessageInner::SendMessageRequest(SendMessageRequest {
                                node_id: self.remote_node_id.to_vec(),
                                debug_msg,
                                data: encrypted_msg_data,
                                syn: false,
                            })),
                        });
                        Ok(())
                    }
                    Err(err) => {
                        error!("unexpected error encrypting message to {}: {}", &self.remote_node_id, err);
                        Err(())
                    }
                }
            }
            _ => {
                verbose!("dropped message to remote {} in {} state", &self.remote_node_id, &self.session);
                Err(())
            }
        }
    }
}

//
// NoiseBuffer impls
//

impl Default for NoiseBuffer {
    fn default() -> Self {
        Self([0; NOISE_CHUNK_MAX_LENGTH])
    }
}

impl AsMut<[u8]> for Box<NoiseBuffer> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

//
// RemoteSender impls
//

impl<M> RemoteCommon for RemoteSender<M>
where M: prost::Message + 'static
{
    fn id(&self) -> &NodeId {
        &self.id
    }

    fn attestation(&self) -> Option<AttestationParameters> {
        self.shared.as_ref().borrow_mut().attestation()
    }
}

impl<M> RemoteMessageSender for RemoteSender<M>
where M: prost::Message + 'static
{
    type Message = M;

    fn send(&self, message: Rc<Self::Message>) -> Result<(), ()> {
        self.shared.as_ref().borrow_mut().send(message)
    }
}

impl<M> fmt::Display for RemoteSender<M>
where M: prost::Message + 'static
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.id(), fmt)
    }
}

impl<M> Clone for RemoteSender<M>
where M: prost::Message + 'static
{
    fn clone(&self) -> Self {
        Self {
            id:     self.id.clone(),
            shared: Rc::clone(&self.shared),
        }
    }
}

//
// AttestationParameters impls
//

impl Copy for AttestationParameters {}
impl Eq for AttestationParameters {}
impl PartialOrd for AttestationParameters {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}
impl Ord for AttestationParameters {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.unix_timestamp_seconds.cmp(&other.unix_timestamp_seconds)
    }
}
impl fmt::Display for AttestationParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_ias_timestamp() {
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.123456789").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.12345678").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.1234567").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.123456").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.12345").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.1234").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.123").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.12").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06.1").is_ok());
        assert!(parse_ias_timestamp("2020-08-01T15:18:06").is_ok());
    }
}
