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
use worker_protos_enclave::storage::storage::*;

use storage::{ORAM_BLOCK_SIZE, ORAM_SIZE};

use std::boxed::Box;
use std::collections::HashMap;

use sgx_tkey_exchange::*;
use sgx_types::*;

use advanca_crypto::*;
use advanca_crypto_types::*;

use serde::Serialize;
use serde_cbor;
use serde_cbor::de::from_slice_with_scratch;
use serde_cbor::ser::SliceWrite;
use serde_cbor::Serializer;

use advanca_macros::{enclave_cryptoerr, enclave_ret, enclave_ret_protobuf};

#[derive(Default, Clone, Copy)]
struct AttestedSession {
    worker_prvkey: Secp256r1PrivateKey,
    worker_pubkey: Secp256r1PublicKey,
    // shared_dhkey  : sgx_ec256_dh_shared_t,
    // kdk           : sgx_key_128bit_t,
}

// public key for Advanca Attestation Service
const G_SP_PUB_KEY: sgx_ec256_public_t = sgx_ec256_public_t {
    gx: [
        0xe3, 0x53, 0x79, 0x5f, 0x40, 0x5b, 0x8a, 0x8f, 0x34, 0x5c, 0xd6, 0xbc, 0x89, 0x1c, 0x49,
        0x6e, 0x9e, 0x56, 0x8e, 0xcb, 0x74, 0xee, 0x43, 0xc1, 0x7d, 0xed, 0xbd, 0x04, 0x0d, 0xea,
        0x4f, 0x1a,
    ],
    gy: [
        0x9c, 0x98, 0x68, 0x5c, 0xbb, 0xb4, 0x9b, 0x67, 0xdd, 0x8d, 0xd2, 0xb6, 0x2a, 0xb0, 0xee,
        0x09, 0x3e, 0xcc, 0x9c, 0x39, 0x1d, 0xa9, 0xc9, 0xce, 0x45, 0xf0, 0xcf, 0xbc, 0x0c, 0x0f,
        0x7d, 0x89,
    ],
};

// TODO: change this to a mutable attested_session data object
// and use once_only init to set the value.
static mut ATTESTED_SESSION: AttestedSession = AttestedSession {
    worker_prvkey: Secp256r1PrivateKey { r: [0; 32] },
    worker_pubkey: Secp256r1PublicKey {
        gx: [0; 32],
        gy: [0; 32],
    },
};
// static mut ATTESTED_SESSION: Once = Once::new();

#[derive(Default, Clone, Copy)]
struct TaskInfo {
    task_prvkey: Secp256r1PrivateKey,
    task_pubkey: Secp256r1PublicKey,
    user_pubkey: Secp256r1PublicKey,
    kdk: Aes128Key,
}

static mut TASKS: *mut HashMap<[u8; 32], TaskInfo> = 0 as *mut HashMap<[u8; 32], TaskInfo>;
static mut SINGLE_TASK: TaskInfo = TaskInfo {
    task_prvkey: Secp256r1PrivateKey { r: [0; 32] },
    task_pubkey: Secp256r1PublicKey {
        gx: [0; 32],
        gy: [0; 32],
    },
    user_pubkey: Secp256r1PublicKey {
        gx: [0; 32],
        gy: [0; 32],
    },
    kdk: Aes128Key { key: [0; 16] },
};

#[no_mangle]
pub unsafe extern "C" fn enclave_init() -> sgx_status_t {
    println!("[ENCLAVE INFO] Before SqrtOram call.");
    SqrtOram::open("oram", ORAM_SIZE, ORAM_BLOCK_SIZE);

    println!("[ENCLAVE INFO] enclave initialized");
    let heap_hashmap = Box::new(HashMap::<[u8; 32], TaskInfo>::new());
    TASKS = Box::into_raw(heap_hashmap);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn enclave_init_ra(b_pse: i32, p_context: &mut sgx_ra_context_t) -> sgx_status_t {
    let ret: sgx_status_t;
    match rsgx_ra_init(&G_SP_PUB_KEY, b_pse) {
        Ok(p) => {
            *p_context = p;
            ret = sgx_status_t::SGX_SUCCESS;
        }
        Err(x) => {
            ret = x;
            return ret;
        }
    }
    ret
}

#[no_mangle]
pub unsafe extern "C" fn enclave_ra_close(context: sgx_ra_context_t) -> sgx_status_t {
    // we'll reinit the hashmap of accepted jobs
    // we'll take back ownership of the box
    // which will be freed when the box is destroyed
    let _old_tasks = Box::from_raw(TASKS);
    let heap_hashmap = Box::new(HashMap::<[u8; 32], TaskInfo>::new());
    TASKS = Box::into_raw(heap_hashmap);

    // Zero out the keys
    ATTESTED_SESSION = AttestedSession::default();

    match rsgx_ra_close(context) {
        Ok(()) => sgx_status_t::SGX_SUCCESS,
        Err(x) => x,
    }
}

#[no_mangle]
pub unsafe extern "C" fn gen_worker_ec256_pubkey() -> sgx_status_t {
    match secp256r1_gen_keypair() {
        Ok((prvkey, pubkey)) => {
            ATTESTED_SESSION.worker_prvkey = prvkey;
            ATTESTED_SESSION.worker_pubkey = pubkey;
            return sgx_status_t::SGX_SUCCESS;
        }
        Err(CryptoError::SgxError(i, _)) => {
            return sgx_status_t::from_repr(i).unwrap();
        }
        _ => unreachable!(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_worker_ec256_pubkey(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
) -> sgx_status_t {
    enclave_ret!(ATTESTED_SESSION.worker_pubkey, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_task_ec256_pubkey(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
    p_task_id: *const u8,
) -> sgx_status_t {
    let mut task_id = [0_u8; 32];
    let task_id_slice = core::slice::from_raw_parts(p_task_id, 32);
    task_id.copy_from_slice(&task_id_slice);
    let task_info = (*TASKS).get(&task_id).unwrap();
    let task_pubkey = task_info.task_pubkey;
    let worker_prvkey = ATTESTED_SESSION.worker_prvkey;
    let signed_pubkey: Secp256r1SignedMsg =
        secp256r1_sign_msg(&worker_prvkey, &serde_cbor::to_vec(&task_pubkey).unwrap()).unwrap();
    enclave_ret!(signed_pubkey, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn gen_worker_reg_request(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
    context: sgx_ra_context_t,
) -> sgx_status_t {
    let pubkey = ATTESTED_SESSION.worker_pubkey;
    let sk_key = enclave_cryptoerr!(enclave_get_sk_key(context));
    let data = pubkey.to_raw_bytes();
    let mac = enclave_cryptoerr!(aes128cmac_mac(&sk_key, &data));
    let req = AasRegRequest {
        worker_pubkey: pubkey,
        mac: mac,
    };
    enclave_ret!(req, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn accept_task(
    p_task_id: *const u8,
    p_user_pubkey_buf: *const u8,
    user_pubkey_buf_size: usize,
) -> sgx_status_t {
    let mut scratch = [0_u8; 8196];
    let mut task_id = [0_u8; 32];
    let task_id_slice = core::slice::from_raw_parts(p_task_id, 32);
    task_id.copy_from_slice(&task_id_slice);
    let pubkey_buf_slice = core::slice::from_raw_parts(p_user_pubkey_buf, user_pubkey_buf_size);
    let user_pubkey: Secp256r1PublicKey =
        from_slice_with_scratch(&pubkey_buf_slice, &mut scratch).unwrap();
    let (task_prvkey, task_pubkey) = secp256r1_gen_keypair().unwrap();

    let kdk = enclave_cryptoerr!(derive_kdk(&task_prvkey, &user_pubkey));
    let task_info = TaskInfo {
        task_prvkey: task_prvkey,
        task_pubkey: task_pubkey,
        user_pubkey: user_pubkey,
        kdk: kdk,
    };
    (*TASKS).insert(task_id, task_info);
    // TODO! hack for single task demo
    SINGLE_TASK.task_prvkey = task_prvkey;
    SINGLE_TASK.task_pubkey = task_pubkey;
    SINGLE_TASK.user_pubkey = user_pubkey;
    SINGLE_TASK.kdk = kdk;
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn encrypt_msg(
    p_ubuf: *mut u8,
    p_ubuf_size: *mut usize,
    p_task_id: *const u8,
    p_msg_in: *const u8,
    msg_in_len: usize,
) -> sgx_status_t {
    let mut task_id = [0_u8; 32];
    task_id.copy_from_slice(core::slice::from_raw_parts(p_task_id, 32));
    let task_info = (*TASKS).get(&task_id).unwrap();
    let kdk = task_info.kdk;
    // TODO: Add a canary at the end of the 2 buffers to ensure that they are of the correct
    // length.
    let data_slice = core::slice::from_raw_parts(p_msg_in, msg_in_len as usize);
    let encrypted_msg = enclave_cryptoerr!(aes128gcm_encrypt(&kdk, &data_slice));
    enclave_ret!(encrypted_msg, p_ubuf, p_ubuf_size);
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
pub unsafe extern "C" fn create_storage(
    public_key: *const u8,
    public_key_size: u32,
) -> sgx_status_t {
    println!("[ENCLAVE INFO] creating storage ...");
    let key_bytes_slice = slice::from_raw_parts(public_key, public_key_size as usize);
    let pubkey: Secp256r1PublicKey = serde_cbor::from_slice(&key_bytes_slice).unwrap();
    let mut key_bytes = [0_u8; 64];
    key_bytes.copy_from_slice(&pubkey.to_raw_bytes());
    if let Err(status) = storage::create_sealed_storage(key_bytes) {
        println!("[ENCLAVE ERROR] create sealed storage failed");
        return status;
    }
    println!("[ENCLAVE INFO] created sealed storage");
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn proc_heartbeat(
    p_ubuf: *mut u8,
    p_ubuf_size: &mut usize,
    p_msg_in: *const u8,
    msg_in_len: usize,
) -> sgx_status_t {
    let heartbeat_req_bytes_slice = core::slice::from_raw_parts(p_msg_in, msg_in_len);
    let heartbeat_req = parse_from_bytes::<HeartbeatRequest>(&heartbeat_req_bytes_slice).unwrap();
    let mut block_hash = heartbeat_req.block_hash;
    if block_hash.len() != 32 {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let mut task_id = [0_u8; 32];
    task_id.copy_from_slice(&heartbeat_req.task_id);
    let task_info = (*TASKS).get(&task_id).unwrap();
    let worker_task_prvkey = task_info.task_prvkey;
    let mut heartbeat_response = HeartbeatResponse::new();

    block_hash.append(&mut b"dokidoki".to_vec());
    let block_hash_mac = enclave_cryptoerr!(secp256r1_sign_msg(&worker_task_prvkey, &block_hash));
    heartbeat_response.heartbeat_sig = serde_cbor::to_vec(&block_hash_mac).unwrap();
    enclave_ret_protobuf!(heartbeat_response, p_ubuf, p_ubuf_size);
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

    let encrypted_msg_slice = slice::from_raw_parts(request, request_size as usize);
    let response_payload = slice::from_raw_parts_mut(response, response_capacity as usize);

    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);

    let encrypted_msg = serde_cbor::from_slice(&encrypted_msg_slice).unwrap();
    let decrypted_msg = enclave_cryptoerr!(aes128gcm_decrypt(&kdk, &encrypted_msg));

    let request_decrypted = decrypted_msg;

    let request_decoded = parse_from_bytes::<PlainRequest>(&request_decrypted).unwrap();
    println!("[ENCLAVE DEBUG] <PlainRequest> {:?}", request_decoded);
    let response = match storage::storage_request(request_decoded) {
        Ok(response) => response,
        Err(status) => return status,
    };
    println!("[ENCLAVE DEBUG] <PlainResponse> {:?}", response);

    let response_encoded = response.write_to_bytes().unwrap();
    let response_encrypted = enclave_cryptoerr!(aes128gcm_encrypt(&kdk, &response_encoded));
    let response_encrypted_bytes = serde_cbor::to_vec(&response_encrypted).unwrap();

    let (first, _) = response_payload.split_at_mut(response_encrypted_bytes.len());
    first.clone_from_slice(&response_encrypted_bytes);
    *response_size = response_encrypted_bytes.len() as u32;

    sgx_status_t::SGX_SUCCESS
}
