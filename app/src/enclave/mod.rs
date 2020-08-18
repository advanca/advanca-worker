// Copyright (C) 2020 ADVANCA PTE. LTD.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    str,
};

use log::{debug, info, trace, warn};

pub use sgx_types::*;
pub use sgx_urts::SgxEnclave;

use advanca_crypto_types::*;

use protobuf::parse_from_bytes;
use protobuf::Message;
use worker_protos_std::storage::storage::*;

use crate::worker_teaclave_ecall as enclave_ecall;
use crate::worker_teaclave_ecall::*;
use advanca_macros::*;

pub const PAYLOAD_MAX_SIZE: usize = 4196;

pub static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_FILE: &'static str = "enclave.signed.so";

pub fn heartbeat_challenge(
    eid: sgx_enclave_id_t,
    heartbeat_req: HeartbeatRequest,
) -> HeartbeatResponse {
    let mut buf: [u8; 4096] = [0; 4096];
    let mut buf_size = 4096;
    let heartbeat_req_bytes = heartbeat_req.write_to_bytes().unwrap();
    let _ = unsafe {
        handle_ecall!(
            eid,
            proc_heartbeat(
                buf.as_mut_ptr(),
                &mut buf_size,
                heartbeat_req_bytes.as_ptr(),
                heartbeat_req_bytes.len()
            )
        )
        .unwrap()
    };
    let heartbeat_reponse = parse_from_bytes::<HeartbeatResponse>(&buf[..buf_size]).unwrap();
    heartbeat_reponse
}

pub fn init() -> SgxResult<SgxEnclave> {
    const LAUNCH_TOKEN_LENGTH: usize = 1024;
    let mut launch_token = [0; LAUNCH_TOKEN_LENGTH];
    let mut launch_token_updated = 0;

    let token_file = Path::new(ENCLAVE_TOKEN);
    if let Ok(mut f) = File::open(&token_file) {
        if let Ok(length) = f.read(&mut launch_token) {
            if length == LAUNCH_TOKEN_LENGTH {
                trace!("valid token file")
            } else {
                warn!("token file seems invalid, new one will be created");
            }
        }
    } else {
        warn!("token file {} not found", token_file.to_str().unwrap());
    }

    let debug = 1;

    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    debug!("creating enclave ...");
    let enclave = (SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    ))?;
    debug!("enclave created");

    if launch_token_updated != 0 {
        if let Ok(mut f) = File::create(&token_file) {
            if f.write_all(&launch_token).is_ok() {
                info!("saved new launch token")
            }
        }
    }

    debug!("initializaing enclave ...");
    let _ = unsafe { handle_ecall!(enclave.geteid(), enclave_init()).unwrap() };
    debug!("done!");
    Ok(enclave)
}

pub fn enclave_sr25519_public_key(eid: sgx_enclave_id_t) -> SgxResult<Sr25519PublicKey> {
    let mut buf_size = 1024;
    let mut buf = vec![0_u8; buf_size];

    let _ = unsafe {
        handle_ecall!(
            eid,
            get_worker_sr25519_pubkey(buf.as_mut_ptr(), &mut buf_size)
        )
        .unwrap()
    };

    let publickey: Sr25519PublicKey = serde_json::from_slice(&buf[..buf_size]).unwrap();

    Ok(publickey)
}

pub fn create_storage(eid: sgx_enclave_id_t, owner: Secp256r1PublicKey) -> SgxError {
    let public_key_bytes = serde_json::to_vec(&owner).unwrap();

    // we'll keep the current interface
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        enclave_ecall::create_storage(
            eid,
            &mut status,
            public_key_bytes.as_ptr(),
            public_key_bytes.len() as u32,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    Ok(())
}

pub fn storage_request(eid: sgx_enclave_id_t, payload: &[u8]) -> SgxResult<Vec<u8>> {
    let mut output = [0 as u8; PAYLOAD_MAX_SIZE];
    let mut response_size: u32 = 0;
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        enclave_ecall::storage_request(
            eid,
            &mut status,
            payload.as_ptr(),
            payload.len() as u32,
            output.as_mut_ptr(),
            output.len() as u32,
            &mut response_size,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    trace!("enclave storage_request returned");
    Ok(output[..response_size as usize].to_vec())
}
