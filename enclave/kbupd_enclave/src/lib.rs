//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#![crate_type = "staticlib"]
#![cfg_attr(not(any(test, feature = "test")), no_std)]
#![cfg_attr(not(any(test, feature = "test")), feature(alloc_error_handler))]
#![cfg_attr(not(any(test, feature = "test")), feature(thread_local))]
#![allow(unused_parens, clippy::style, clippy::large_enum_variant)]
#![warn(
    bare_trait_objects,
    elided_lifetimes_in_paths,
    trivial_numeric_casts,
    variant_size_differences,
    clippy::integer_arithmetic,
    clippy::wildcard_enum_match_arm
)]
#![deny(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::clone_on_ref_ptr,
    clippy::expl_impl_clone_on_copy,
    clippy::explicit_into_iter_loop,
    clippy::explicit_iter_loop,
    clippy::float_arithmetic,
    clippy::float_cmp_const,
    clippy::indexing_slicing,
    clippy::maybe_infinite_iter,
    clippy::mem_forget,
    clippy::mut_mut,
    clippy::needless_borrow,
    clippy::option_unwrap_used,
    clippy::panicking_unwrap,
    clippy::print_stdout,
    clippy::redundant_clone,
    clippy::replace_consts,
    clippy::result_unwrap_used,
    clippy::shadow_unrelated,
    clippy::unimplemented,
    clippy::use_debug,
    clippy::use_self,
    clippy::use_underscore_binding
)]

extern crate alloc;

#[cfg(not(any(test, feature = "test")))]
extern crate no_std_compat as std;

#[cfg(not(any(test, feature = "test")))]
#[global_allocator]
static ALLOCATOR: allocator::System = allocator::System;

#[macro_use]
mod macros;

#[cfg(not(any(test, feature = "test")))]
mod allocator;
mod ffi;
mod hasher;
mod logging;
mod lru;
mod prelude;
#[allow(clippy::all, clippy::pedantic, clippy::integer_arithmetic)]
mod protobufs;
mod protobufs_impl;
mod raft;
mod remote;
mod remote_group;
mod service;
mod storage;
mod util;

pub use crate::ffi::ecalls::{kbupd_send, kbupd_send_flush};

pub mod external {
    use sgx_ffi::sgx::SgxStatus;
    use sgxsd_ffi::ecalls::SgxsdServer;

    use crate::service::main;

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_init(
        p_args: *const <main::SgxsdState as SgxsdServer>::InitArgs,
        pp_state: *mut *mut main::SgxsdState,
    ) -> SgxStatus
    {
        sgxsd_ffi::ecalls::sgxsd_enclave_server_init(p_args, pp_state)
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_handle_call(
        p_args: *const <main::SgxsdState as SgxsdServer>::HandleCallArgs,
        msg_buf: sgxsd_ffi::ecalls::sgxsd_msg_buf_t,
        mut from: sgxsd_ffi::ecalls::sgxsd_msg_from_t,
        pp_state: *mut *mut main::SgxsdState,
    ) -> SgxStatus
    {
        sgxsd_ffi::ecalls::sgxsd_enclave_server_handle_call(p_args, msg_buf, &mut from, pp_state)
    }

    #[no_mangle]
    pub extern "C" fn sgxsd_enclave_server_terminate(
        p_args: *const <main::SgxsdState as SgxsdServer>::TerminateArgs,
        p_state: *mut main::SgxsdState,
    ) -> SgxStatus
    {
        sgxsd_ffi::ecalls::sgxsd_enclave_server_terminate(p_args, p_state)
    }

    #[no_mangle]
    pub extern "C" fn kbupd_enclave_recv_untrusted_msg(p_data: *const u8, data_size: usize) {
        crate::service::main::whereis(|service_ref| {
            let mut service = service_ref.borrow_mut();
            crate::ffi::ecalls::kbupd_enclave_recv_untrusted_msg(&mut *service, p_data, data_size)
        });
    }
}
