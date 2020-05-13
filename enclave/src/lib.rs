// Copyright 2020 ADVANCA PTE. LTD.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![crate_name = "advanca_worker_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod constants;
mod io;
mod rsa3072;
mod storage;
mod utils;

use std::backtrace::{self, PrintFormat};

use oram::SqrtOram;
use protobuf::parse_from_bytes;
use protobuf::Message;
use protos::storage::*;
use serde_json;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use std::slice;
use storage::{ORAM_BLOCK_SIZE, ORAM_SIZE};
use utils::write_slice_and_whitespace_pad;

use sgx_types::*;
use core::mem::size_of;

use std::collections::HashMap;
use std::boxed::Box;

use sgx_types::*;
use sgx_tkey_exchange::*;

use sgx_types::sgx_ra_key_type_t::*;

use advanca_crypto_ctypes::{CSgxEphemeralKey, CAasRegRequest};
use advanca_crypto::sgx_enclave;
use advanca_crypto::sgx_enclave::sgx_enclave_utils as enclave_utils;
//use std::sync::Once;

#[derive(Default, Clone, Copy)]
struct AttestedSession {
    worker_prvkey : sgx_ec256_private_t,
    worker_pubkey : sgx_ec256_public_t,
    // shared_dhkey  : sgx_ec256_dh_shared_t,
    // kdk           : sgx_key_128bit_t,
}

// public key for Advanca Attestation Service
const G_SP_PUB_KEY : sgx_ec256_public_t = sgx_ec256_public_t {
gx: [
        0xe3,0x53,0x79,0x5f,0x40,0x5b,0x8a,0x8f,0x34,0x5c,0xd6,0xbc,0x89,0x1c,0x49,0x6e,
        0x9e,0x56,0x8e,0xcb,0x74,0xee,0x43,0xc1,0x7d,0xed,0xbd,0x04,0x0d,0xea,0x4f,0x1a,
    ],
gy: [
        0x9c,0x98,0x68,0x5c,0xbb,0xb4,0x9b,0x67,0xdd,0x8d,0xd2,0xb6,0x2a,0xb0,0xee,0x09,
        0x3e,0xcc,0x9c,0x39,0x1d,0xa9,0xc9,0xce,0x45,0xf0,0xcf,0xbc,0x0c,0x0f,0x7d,0x89,
    ],
};

// TODO: change this to a mutable attested_session data object
// and use once_only init to set the value.
static mut ATTESTED_SESSION: AttestedSession = 
AttestedSession {
    worker_prvkey: sgx_ec256_private_t {
        r: [0;32],
    },
    worker_pubkey: sgx_ec256_public_t {
        gx: [0;32],
        gy: [0;32],
    },
    // shared_dhkey: sgx_ec256_dh_shared_t {
    //     s: [0;32],
    // },
    // kdk: [0;16],
};
// static mut ATTESTED_SESSION: Once = Once::new();

#[derive(Default, Clone, Copy)]
struct TaskInfo {
    user_pubkey  : sgx_ec256_public_t,
    shared_dhkey : sgx_ec256_dh_shared_t,
    kdk          : sgx_key_128bit_t,
}

static mut TASKS: *mut HashMap<u32, TaskInfo> = 0 as *mut HashMap<u32, TaskInfo>;


#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
    if let Err(status) = rsa3072::create_sealed_if_absent() {
        return status;
    }

    println!("[ENCLAVE INFO] Before SqrtOram call.");
    SqrtOram::open("oram", ORAM_SIZE, ORAM_BLOCK_SIZE);

    println!("[ENCLAVE INFO] enclave initialized");
    let heap_hashmap = Box::new(HashMap::<u32, TaskInfo>::new());
    unsafe { TASKS = Box::into_raw(heap_hashmap) };
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn enclave_init_ra (b_pse: i32,
                                   p_context: &mut sgx_ra_context_t) -> sgx_status_t {
    let ret: sgx_status_t;
    match rsgx_ra_init(&G_SP_PUB_KEY, b_pse) {
        Ok(p) => {
            *p_context = p;
            ret = sgx_status_t::SGX_SUCCESS;
        },
        Err(x) => {
            ret = x;
            return ret;
        }
    }
    ret
}

#[no_mangle]
pub extern "C" fn enclave_ra_close (context: sgx_ra_context_t) -> sgx_status_t {
    // we'll reinit the hashmap of accepted jobs
    // we'll take back ownership of the box
    // which will be freed when the box is destroyed
    let _old_tasks = unsafe{Box::from_raw(TASKS)};
    let heap_hashmap = Box::new(HashMap::<u32, TaskInfo>::new());
    unsafe { TASKS = Box::into_raw(heap_hashmap) };

    // Zero out the keys
    unsafe { ATTESTED_SESSION = AttestedSession::default() };

    match rsgx_ra_close(context) {
        Ok(()) => {
            sgx_status_t::SGX_SUCCESS
        },
        Err(x) => x
    }
}

#[no_mangle]
pub extern "C" fn gen_worker_ec256_pubkey (
    ) -> sgx_status_t {

    let mut p_ecc_handle:sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    // TODO: this is not thread safe!!!
    // SINGLE THREAD ONLY!!!
    let p_private = unsafe{&mut ATTESTED_SESSION.worker_prvkey};
    let p_public  = unsafe{&mut ATTESTED_SESSION.worker_pubkey};

    let mut ret;
    ret = unsafe {sgx_ecc256_open_context(&mut p_ecc_handle)};
    if ret == sgx_status_t::SGX_SUCCESS {
        ret = unsafe {sgx_ecc256_create_key_pair(p_private, p_public, p_ecc_handle)};
    }
    if ret == sgx_status_t::SGX_SUCCESS {
        ret = unsafe {sgx_ecc256_close_context(p_ecc_handle)};
    }
    ret
}

#[no_mangle]
pub extern "C" fn gen_worker_reg_request(
    context: sgx_ra_context_t,
    aas_reg_request: &mut CAasRegRequest,
) -> sgx_status_t {
    let p_public_ptr = unsafe{&ATTESTED_SESSION.worker_pubkey as *const sgx_ec256_public_t};
    let data_slice = unsafe{core::slice::from_raw_parts(p_public_ptr as *const u8, size_of::<sgx_ec256_public_t>())};
    let mut mac = sgx_cmac_128bit_tag_t::default();

    let ret = enclave_utils::aes128_cmac_sk(context, &data_slice, &mut mac);
    if ret == sgx_status_t::SGX_SUCCESS {
        aas_reg_request.pubkey = unsafe{ATTESTED_SESSION.worker_pubkey};
        aas_reg_request.mac    = mac;
    }
    ret
}

#[no_mangle]
pub extern "C" fn accept_task (
    user_pubkey : sgx_ec256_public_t,
    task_id     : &mut u32,
) -> sgx_status_t {
    let mut task_id = 0;
    loop {
        // get a random u32 number
        let mut num_buf = [0;4];
        let ret = unsafe {sgx_read_rand(num_buf.as_mut_ptr(), 4 as usize)};
        if ret == sgx_status_t::SGX_SUCCESS {
            // check if number exists in tasks
            let random_taskid = u32::from_be_bytes(num_buf);
            if unsafe{(*TASKS).contains_key(&random_taskid)} {
                task_id = random_taskid;
                break;
            }
        } else {
            return ret;
        }
    }
    unsafe {(*TASKS).insert(task_id, TaskInfo::default())};
    sgx_status_t::SGX_SUCCESS
}




#[no_mangle]
pub unsafe extern "C" fn get_sr25519_public_key(
    public_key: *mut u8,
    public_key_size: u32,
) -> sgx_status_t {
    let key_slice = slice::from_raw_parts_mut(public_key, public_key_size as usize);

    //FIXME: a dummy public key is used
    key_slice.clone_from_slice(&[111 as u8; 32]);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa3072_public_key(
    public_key: *mut u8,
    public_key_size: u32,
) -> sgx_status_t {
    let public_key_slice = slice::from_raw_parts_mut(public_key, public_key_size as usize);

    let rsa_public_key = match rsa3072::unseal_pubkey() {
        Ok(key) => key,
        Err(status) => return status,
    };

    let rsa_public_key_json = match serde_json::to_string(&rsa_public_key) {
        Ok(k) => k,
        Err(x) => {
            println!(
                "[ENCLAVE ERROR] can't serialize rsa_public_key {:?} {}",
                rsa_public_key, x
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    write_slice_and_whitespace_pad(public_key_slice, rsa_public_key_json.as_bytes().to_vec());
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn create_storage(
    public_key: *const u8,
    public_key_size: u32,
) -> sgx_status_t {
    println!("[ENCLAVE INFO] creating storage ...");
    let key_bytes = slice::from_raw_parts(public_key, public_key_size as usize);
    let key_str = std::str::from_utf8(key_bytes).unwrap();
    let key: Rsa3072PubKey = serde_json::from_str(&key_str).unwrap();
    if let Err(status) = storage::create_sealed_storage(key) {
        println!("[ENCLAVE ERROR] create sealed storage failed");
        return status;
    }
    println!("[ENCLAVE INFO] created sealed storage");
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn storage_request(
    request: *const u8,
    request_size: u32,
    response: *mut u8,
    response_capacity: u32,
    response_size: *mut u32,
) -> sgx_status_t {
    let request_payload = slice::from_raw_parts(request, request_size as usize);
    let response_payload = slice::from_raw_parts_mut(response, response_capacity as usize);

    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);

    let keypair = match rsa3072::unseal_pair() {
        Ok(keypair) => keypair,
        Err(status) => return status,
    };
    let request_decrypted = rsa3072::decrypt(request_payload, &keypair);
    let request_decoded = parse_from_bytes::<PlainRequest>(&request_decrypted).unwrap();
    println!("[ENCLAVE DEBUG] <PlainRequest> {:?}", request_decoded);
    let response = match storage::storage_request(request_decoded) {
        Ok(response) => response,
        Err(status) => return status,
    };
    println!("[ENCLAVE DEBUG] <PlainResponse> {:?}", response);

    let owner = storage::unseal_owner().unwrap();

    let response_encoded = response.write_to_bytes().unwrap();
    let response_encrypted = rsa3072::encrypt(&response_encoded, &owner);

    let (first, _) = response_payload.split_at_mut(response_encrypted.len());
    first.clone_from_slice(&response_encrypted);
    *response_size = response_encrypted.len() as u32;

    sgx_status_t::SGX_SUCCESS
}
