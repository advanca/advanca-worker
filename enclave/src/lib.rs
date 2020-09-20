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
use std::convert::TryInto;

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

use advanca_macros::{enclave_cryptoerr, enclave_ret, enclave_ret_protobuf};

#[derive(Default, Clone, Copy)]
struct AttestedSession {
    enclave_secp256r1_prvkey: Secp256r1PrivateKey,
    enclave_secp256r1_pubkey: Secp256r1PublicKey,
    enclave_sr25519_prvkey: Sr25519PrivateKey,
    enclave_sr25519_pubkey: Sr25519PublicKey,
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
    enclave_secp256r1_prvkey: Secp256r1PrivateKey { r: [0; 32] },
    enclave_secp256r1_pubkey: Secp256r1PublicKey {
        gx: [0; 32],
        gy: [0; 32],
    },
    enclave_sr25519_prvkey: Sr25519PrivateKey {
        secret: [0; 32],
        nonce: [0; 32],
    },
    enclave_sr25519_pubkey: Sr25519PublicKey {
        compressed_point: [0; 32],
    },
};
// static mut ATTESTED_SESSION: Once = Once::new();

#[derive(Default, Clone, Copy)]
struct TaskInfo {
    task_secp256r1_prvkey: Secp256r1PrivateKey,
    task_secp256r1_pubkey: Secp256r1PublicKey,
    task_sr25519_prvkey: Sr25519PrivateKey,
    task_sr25519_pubkey: Sr25519PublicKey,
    user_secp256r1_pubkey: Secp256r1PublicKey,
    user_sr25519_pubkey: Sr25519PublicKey,
    kdk: Aes128Key,
    enclave_total_in: usize,
    enclave_total_out: usize,
    compute_amt: usize,
}

static mut TASKS: *mut HashMap<[u8; 32], TaskInfo> = 0 as *mut HashMap<[u8; 32], TaskInfo>;
static mut SINGLE_TASK: TaskInfo = TaskInfo {
    task_secp256r1_prvkey: Secp256r1PrivateKey { r: [0; 32] },
    task_secp256r1_pubkey: Secp256r1PublicKey {
        gx: [0; 32],
        gy: [0; 32],
    },
    task_sr25519_prvkey: Sr25519PrivateKey {
        secret: [0; 32],
        nonce: [0; 32],
    },
    task_sr25519_pubkey: Sr25519PublicKey {
        compressed_point: [0; 32],
    },
    user_secp256r1_pubkey: Secp256r1PublicKey {
        gx: [0; 32],
        gy: [0; 32],
    },
    user_sr25519_pubkey: Sr25519PublicKey {
        compressed_point: [0; 32],
    },
    kdk: Aes128Key { key: [0; 16] },
    enclave_total_in: 0,
    enclave_total_out: 0,
    compute_amt: 0,
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
pub unsafe extern "C" fn gen_worker_key() -> sgx_status_t {
    match secp256r1_gen_keypair() {
        Ok((prvkey, pubkey)) => {
            ATTESTED_SESSION.enclave_secp256r1_prvkey = prvkey;
            ATTESTED_SESSION.enclave_secp256r1_pubkey = pubkey;
        }
        Err(CryptoError::SgxError(i, _)) => {
            return sgx_status_t::from_repr(i).unwrap();
        }
        _ => unreachable!(),
    }
    match sr25519_gen_keypair() {
        Ok((prvkey, pubkey)) => {
            ATTESTED_SESSION.enclave_sr25519_prvkey = prvkey;
            ATTESTED_SESSION.enclave_sr25519_pubkey = pubkey;
        }
        Err(CryptoError::SgxError(i, _)) => {
            return sgx_status_t::from_repr(i).unwrap();
        }
        _ => unreachable!(),
    }
    return sgx_status_t::SGX_SUCCESS;
}

#[no_mangle]
pub unsafe extern "C" fn get_worker_sr25519_pubkey(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
) -> sgx_status_t {
    enclave_ret!(ATTESTED_SESSION.enclave_sr25519_pubkey, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_task_sr25519_pubkey(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
    p_task_id: *const u8,
) -> sgx_status_t {
    let mut task_id = [0_u8; 32];
    let task_id_slice = core::slice::from_raw_parts(p_task_id, 32);
    task_id.copy_from_slice(&task_id_slice);
    let task_info = (*TASKS).get(&task_id).unwrap();
    let task_sr25519_pubkey: Sr25519PublicKey = task_info.task_sr25519_pubkey;
    let enclave_sr25519_prvkey = ATTESTED_SESSION.enclave_sr25519_prvkey;
    let signed_pubkey: Sr25519SignedMsg = sr25519_sign_msg(
        &enclave_sr25519_prvkey,
        &serde_json::to_vec(&task_sr25519_pubkey).unwrap(),
    )
    .unwrap();
    enclave_ret!(signed_pubkey, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_worker_ec256_pubkey(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
) -> sgx_status_t {
    enclave_ret!(ATTESTED_SESSION.enclave_secp256r1_pubkey, ubuf, ubuf_size);
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
    let task_pubkey = task_info.task_secp256r1_pubkey;
    let enclave_secp256r1_prvkey = ATTESTED_SESSION.enclave_secp256r1_prvkey;
    let signed_pubkey: Secp256r1SignedMsg = secp256r1_sign_msg(
        &enclave_secp256r1_prvkey,
        &serde_json::to_vec(&task_pubkey).unwrap(),
    )
    .unwrap();
    enclave_ret!(signed_pubkey, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn gen_worker_reg_request(
    ubuf: *mut u8,
    ubuf_size: &mut usize,
    context: sgx_ra_context_t,
) -> sgx_status_t {
    let secp256r1_pubkey = ATTESTED_SESSION.enclave_secp256r1_pubkey;
    let sr25519_pubkey = ATTESTED_SESSION.enclave_sr25519_pubkey;
    let mut req = AasRegRequest {
        enclave_secp256r1_pubkey: secp256r1_pubkey,
        enclave_sr25519_pubkey: sr25519_pubkey,
        mac: Aes128Mac::default(),
    };
    let sk_key = enclave_cryptoerr!(enclave_get_sk_key(context));
    let mac = enclave_cryptoerr!(aes128cmac_mac(&sk_key, &req.to_check_bytes()));
    req.mac = mac;
    enclave_ret!(req, ubuf, ubuf_size);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn accept_task(
    p_task_id: *const u8,
    p_user_pubkey_secp256r1_buf: *const u8,
    user_pubkey_secp256r1_buf_size: usize,
    p_user_pubkey_sr25519_buf: *const u8,
    user_pubkey_sr25519_buf_size: usize,
) -> sgx_status_t {
    let mut task_id = [0_u8; 32];
    let task_id_slice = core::slice::from_raw_parts(p_task_id, 32);
    task_id.copy_from_slice(&task_id_slice);

    let pubkey_secp256r1_buf_slice =
        core::slice::from_raw_parts(p_user_pubkey_secp256r1_buf, user_pubkey_secp256r1_buf_size);
    let user_secp256r1_pubkey: Secp256r1PublicKey =
        serde_json::from_slice(pubkey_secp256r1_buf_slice).unwrap();

    let pubkey_sr25519_buf_slice =
        core::slice::from_raw_parts(p_user_pubkey_sr25519_buf, user_pubkey_sr25519_buf_size);
    let user_sr25519_pubkey: Sr25519PublicKey =
        serde_json::from_slice(pubkey_sr25519_buf_slice).unwrap();

    let (task_secp256r1_prvkey, task_secp256r1_pubkey) = secp256r1_gen_keypair().unwrap();
    let (task_sr25519_prvkey, task_sr25519_pubkey) = sr25519_gen_keypair().unwrap();

    let kdk = enclave_cryptoerr!(derive_kdk(&task_secp256r1_prvkey, &user_secp256r1_pubkey));
    let task_info = TaskInfo {
        task_secp256r1_prvkey: task_secp256r1_prvkey,
        task_secp256r1_pubkey: task_secp256r1_pubkey,
        task_sr25519_prvkey: task_sr25519_prvkey,
        task_sr25519_pubkey: task_sr25519_pubkey,
        user_secp256r1_pubkey: user_secp256r1_pubkey,
        user_sr25519_pubkey: user_sr25519_pubkey,
        kdk: kdk,
        enclave_total_in: 0,
        enclave_total_out: 0,
        compute_amt: 0,
    };
    (*TASKS).insert(task_id, task_info);
    // TODO! hack for single task demo
    SINGLE_TASK.task_secp256r1_prvkey = task_secp256r1_prvkey;
    SINGLE_TASK.task_secp256r1_pubkey = task_secp256r1_pubkey;
    SINGLE_TASK.task_sr25519_prvkey = task_sr25519_prvkey;
    SINGLE_TASK.task_sr25519_pubkey = task_sr25519_pubkey;
    SINGLE_TASK.user_secp256r1_pubkey = user_secp256r1_pubkey;
    SINGLE_TASK.user_sr25519_pubkey = task_info.user_sr25519_pubkey;
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
pub unsafe extern "C" fn create_storage(
    public_key: *const u8,
    public_key_size: u32,
) -> sgx_status_t {
    println!("[ENCLAVE INFO] creating storage ...");
    let key_bytes_slice = slice::from_raw_parts(public_key, public_key_size as usize);
    let pubkey: Secp256r1PublicKey = serde_json::from_slice(&key_bytes_slice).unwrap();
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
    let data_in = SINGLE_TASK.enclave_total_in;
    let data_out = SINGLE_TASK.enclave_total_out;

    let heartbeat_req_bytes_slice = core::slice::from_raw_parts(p_msg_in, msg_in_len);
    let heartbeat_req = parse_from_bytes::<HeartbeatRequest>(&heartbeat_req_bytes_slice).unwrap();
    let block_hash = heartbeat_req.block_hash;
    if block_hash.len() != 32 {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let mut task_id = [0_u8; 32];
    task_id.copy_from_slice(&heartbeat_req.task_id);
    let task_info = (*TASKS).get(&task_id).unwrap();
    // let worker_task_prvkey = task_info.task_prvkey;
    let worker_task_sr25519_prvkey = task_info.task_sr25519_prvkey;
    let mut heartbeat_response = HeartbeatResponse::new();
    // obtain the storage info
    // current owner is not used for storage, set it to 0
    // used in the future for multiple owners
    let (storage_in, storage_out, storage_size) = storage::get_storage_stats([0; 64]).unwrap();
    let alive_evidence = AliveEvidence {
        magic_str: *b"dokidoki",
        task_id: task_id.to_vec(),
        block_hash: block_hash,
        data_in: data_in,
        data_out: data_out,
        storage_in: storage_in,
        storage_out: storage_out,
        storage_size: storage_size,
    };
    let data = serde_json::to_vec(&alive_evidence).unwrap();

    // let block_hash_mac = enclave_cryptoerr!(secp256r1_sign_msg(&worker_task_prvkey, &data));
    let block_hash_mac = enclave_cryptoerr!(sr25519_sign_msg(&worker_task_sr25519_prvkey, &data));
    heartbeat_response.heartbeat_sig = serde_json::to_vec(&block_hash_mac).unwrap();
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
    SINGLE_TASK.enclave_total_in += request_size as usize;

    let encrypted_msg_slice = slice::from_raw_parts(request, request_size as usize);
    let response_payload = slice::from_raw_parts_mut(response, response_capacity as usize);

    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);

    let encrypted_msg = serde_json::from_slice(&encrypted_msg_slice).unwrap();
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
    let response_encrypted_bytes = serde_json::to_vec(&response_encrypted).unwrap();

    let (first, _) = response_payload.split_at_mut(response_encrypted_bytes.len());
    first.clone_from_slice(&response_encrypted_bytes);
    *response_size = response_encrypted_bytes.len() as u32;

    SINGLE_TASK.enclave_total_out += *response_size as usize;
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn demo_compute(
    request: *const u8,
    request_size: u32,
    response: *mut u8,
    response_capacity: u32,
    response_size: *mut u32,
) -> sgx_status_t {
    // Each compute function will define its own compute weight similar to that of
    // the weight for each pallet extrinsic function
    const COMPUTE_WEIGHT: usize = 140000;

    // Updates the enclave accounting stats
    SINGLE_TASK.enclave_total_in += request_size as usize;
    SINGLE_TASK.compute_amt += COMPUTE_WEIGHT;

    // Obtain the shared AES128 key between user and worker
    let kdk = SINGLE_TASK.kdk;

    // Decrypt incoming request from user
    let encrypted_msg_slice = slice::from_raw_parts(request, request_size as usize);
    let response_payload = slice::from_raw_parts_mut(response, response_capacity as usize);
    let encrypted_msg = serde_json::from_slice(&encrypted_msg_slice).unwrap();
    let decrypted_msg = enclave_cryptoerr!(aes128gcm_decrypt(&kdk, &encrypted_msg));

    // In this demo, the decrypted message is 2 u32 values
    let v1 = u32::from_le_bytes(decrypted_msg[..4].try_into().unwrap());
    let v2 = u32::from_le_bytes(decrypted_msg[4..].try_into().unwrap());

    // Perform computation
    let result = v1 + v2;
    let response_bytes = result.to_le_bytes();

    // Encrypt result
    let response_encrypted = enclave_cryptoerr!(aes128gcm_encrypt(&kdk, &response_bytes));
    let response_encrypted_bytes = serde_json::to_vec(&response_encrypted).unwrap();

    // Writes the encrypted response into the array
    let (first, _) = response_payload.split_at_mut(response_encrypted_bytes.len());
    first.clone_from_slice(&response_encrypted_bytes);

    // Writes response size
    *response_size = response_encrypted_bytes.len() as u32;

    // Updates accounting for enclave data out
    SINGLE_TASK.enclave_total_out += *response_size as usize;

    sgx_status_t::SGX_SUCCESS
}
