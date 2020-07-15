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
mod storage;
mod utils;

use std::backtrace::{self, PrintFormat};

use core::slice;
use oram::SqrtOram;
use protobuf::parse_from_bytes;
use protobuf::Message;
use protos::storage::*;
use core::slice;
use storage::{ORAM_BLOCK_SIZE, ORAM_SIZE};

use core::mem::size_of;

use std::collections::HashMap;
use std::boxed::Box;

use sgx_types::*;
use sgx_tkey_exchange::*;

use advanca_crypto_ctypes::{CAasRegRequest};
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

static mut TASKS: *mut HashMap<[u8;32], TaskInfo> = 0 as *mut HashMap<[u8;32], TaskInfo>;
static mut SINGLE_TASK: TaskInfo =
TaskInfo {
    user_pubkey: sgx_ec256_public_t {
        gx: [0;32],
        gy: [0;32],
    },
    shared_dhkey: sgx_ec256_dh_shared_t {
        s: [0;32],
    },
    kdk: [0;16],
};


#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
    println!("[ENCLAVE INFO] Before SqrtOram call.");
    SqrtOram::open("oram", ORAM_SIZE, ORAM_BLOCK_SIZE);

    println!("[ENCLAVE INFO] enclave initialized");
    let heap_hashmap = Box::new(HashMap::<[u8;32], TaskInfo>::new());
    TASKS = Box::into_raw(heap_hashmap);
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
    let heap_hashmap = Box::new(HashMap::<[u8;32], TaskInfo>::new());
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
    worker_pubkey: &mut sgx_ec256_public_t,
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
    *worker_pubkey = *p_public;
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
    task_id     : &[u8;32],
    p_user_pubkey : &sgx_ec256_public_t,
) -> sgx_status_t {
    let mut ret;
    let mut gab_x = sgx_ec256_dh_shared_t::default();

    let worker_prvkey = unsafe{ATTESTED_SESSION.worker_prvkey};

    ret = enclave_utils::derive_ec256_shared_dhkey(p_user_pubkey, &worker_prvkey, &mut gab_x);
    if ret == sgx_status_t::SGX_SUCCESS {
        // derive the kdk from the shared dhkey
        // KDK = AES-CMAC(key0, gab x-coordinate)
        let key0 = sgx_cmac_128bit_key_t::default();
        let p_src = &gab_x as *const sgx_ec256_dh_shared_t as *const u8;
        let src_len = size_of::<sgx_ec256_dh_shared_t>() as u32;
        let mut mac = sgx_cmac_128bit_key_t::default();
        ret = unsafe {sgx_rijndael128_cmac_msg(&key0, p_src, src_len, &mut mac)};
        if ret == sgx_status_t::SGX_SUCCESS {
            let task_info = TaskInfo {
                user_pubkey  : *p_user_pubkey,
                shared_dhkey : gab_x,
                kdk          : mac,
            };
            unsafe {(*TASKS).insert(*task_id, task_info)};

            // TODO! hack for single task demo
            unsafe{SINGLE_TASK.user_pubkey = *p_user_pubkey;}
            unsafe{SINGLE_TASK.shared_dhkey = gab_x;}
            unsafe{SINGLE_TASK.kdk = mac;}
        }
    }
    ret
}

#[no_mangle]
pub extern "C" fn encrypt_msg (
    task_id : &[u8;32],
    msg_in  : *const u8,
    msg_in_len: u32,
    msg_out : *mut u8,
    msg_out_len : u32,
) -> sgx_status_t {
    let task_info = unsafe {(*TASKS).get(task_id).unwrap()};
    let kdk = task_info.kdk;
    // TODO: Add a canary at the end of the 2 buffers to ensure that they are of the correct
    // length.
    let slice_data = unsafe{core::slice::from_raw_parts(msg_in, msg_in_len as usize)};
    let slice_out  = unsafe{core::slice::from_raw_parts_mut(msg_out, msg_out_len as usize)};

    // for security, all buffers are allocated within the enclave and only copied once all
    // operations are successful
    let mut ivcipher = vec![0_u8; msg_out_len as usize];

    println!("slice_data: {:?}", slice_data);
    println!("key: {:?}", kdk);

    let ret = enclave_utils::aes128_gcm_encrypt(&kdk, &slice_data, &[], &mut ivcipher);
    if ret != sgx_status_t::SGX_SUCCESS { return ret; }

    slice_out.copy_from_slice(&ivcipher);
    println!("done!: {:?}", slice_data);
    println!("done!: {:?}", slice_out);

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub unsafe extern "C" fn get_sr25519_public_key(
    public_key: *mut u8,
    public_key_size: u32,
) -> sgx_status_t {
    let p_public_ptr = unsafe { &ATTESTED_SESSION.worker_pubkey as *const sgx_ec256_public_t };
    let data_slice = unsafe {
        core::slice::from_raw_parts(p_public_ptr as *const u8, size_of::<sgx_ec256_public_t>())
    };
    let mut mac = sgx_cmac_128bit_tag_t::default();

    let ret = enclave_utils::aes128_cmac_sk(context, &data_slice, &mut mac);
    if ret == sgx_status_t::SGX_SUCCESS {
        aas_reg_request.pubkey = unsafe { ATTESTED_SESSION.worker_pubkey };
        aas_reg_request.mac = mac;
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn create_storage(
    public_key: *const u8,
    public_key_size: u32,
) -> sgx_status_t {
    println!("[ENCLAVE INFO] creating storage ...");
    assert_eq!(64, public_key_size);
    let key_bytes_slice = slice::from_raw_parts(public_key, public_key_size as usize);
    let mut key_bytes = [0_u8;64];
    key_bytes.copy_from_slice(key_bytes_slice);
    if let Err(status) = storage::create_sealed_storage(key_bytes) {
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
    let kdk = SINGLE_TASK.kdk;

    let request_payload = slice::from_raw_parts(request, request_size as usize);
    let response_payload = slice::from_raw_parts_mut(response, response_capacity as usize);

    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);

    let cipher_len = request_size - 12 - 16;
    let mut decrypted = vec![0_u8; cipher_len as usize];

    let ret = enclave_utils::aes128_gcm_decrypt(&kdk, request_payload, &[], &mut decrypted);
    if ret != sgx_status_t::SGX_SUCCESS {panic!("Decryption failure! {:?}", ret);}
    let request_decrypted = decrypted;

    //let request_decrypted = rsa3072::decrypt(request_payload, &keypair);
    let request_decoded = parse_from_bytes::<PlainRequest>(&request_decrypted).unwrap();
    println!("[ENCLAVE DEBUG] <PlainRequest> {:?}", request_decoded);
    let response = match storage::storage_request(request_decoded) {
        Ok(response) => response,
        Err(status) => return status,
    };
    println!("[ENCLAVE DEBUG] <PlainResponse> {:?}", response);

    let response_encoded = response.write_to_bytes().unwrap();
    let mut response_encrypted = vec![0_u8; 12+16+response_encoded.len()];
    let ret = enclave_utils::aes128_gcm_encrypt(&kdk, &response_encoded, &[], &mut response_encrypted);
    if ret != sgx_status_t::SGX_SUCCESS {panic!("Encryption failure! {:?}", ret);}

    let (first, _) = response_payload.split_at_mut(response_encrypted.len());
    first.clone_from_slice(&response_encrypted);
    *response_size = response_encrypted.len() as u32;

    sgx_status_t::SGX_SUCCESS
}
