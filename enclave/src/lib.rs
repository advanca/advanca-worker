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

use protobuf::parse_from_bytes;
use protobuf::Message;
use protos::storage::*;
use serde_json;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::sgx_status_t;
use std::slice;
use utils::write_slice_and_whitespace_pad;
use oram::SqrtOram;
use storage::{ORAM_SIZE, ORAM_BLOCK_SIZE};

#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
    if let Err(status) = rsa3072::create_sealed_if_absent() {
        return status;
    }

    SqrtOram::open("oram", ORAM_SIZE, ORAM_BLOCK_SIZE);

    println!("[ENCLAVE INFO] enclave initialized");
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
