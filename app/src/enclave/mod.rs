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

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
pub use sgx_types::*;
pub use sgx_urts::SgxEnclave;

use advanca_crypto_types::*;

pub const PAYLOAD_MAX_SIZE: usize = 4196;
mod ecall;

pub static ENCLAVE_TOKEN: &'static str = "enclave.token";
pub static ENCLAVE_FILE: &'static str = "enclave.signed.so";

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

    let mut status = sgx_status_t::SGX_SUCCESS;

    debug!("initializaing enclave ...");
    let result = unsafe { ecall::init(enclave.geteid(), &mut status) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    debug!("done!");
    Ok(enclave)
}

pub fn sr25519_public_key(eid: sgx_enclave_id_t) -> SgxResult<Vec<u8>> {
    let public_key_size = 32;
    let mut public_key = vec![0u8; public_key_size as usize];

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall::get_sr25519_public_key(eid, &mut status, public_key.as_mut_ptr(), public_key_size)
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(public_key)
}

pub fn rsa3072_public_key(eid: sgx_enclave_id_t) -> SgxResult<Vec<u8>> {
    let public_key_size = 8192;
    let mut public_key = vec![0u8; public_key_size as usize];

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall::get_rsa3072_public_key(eid, &mut status, public_key.as_mut_ptr(), public_key_size)
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    let rsa_public_key: Rsa3072PubKey = serde_json::from_slice(&public_key[..]).unwrap();
    trace!("got RSA public key {:?}", rsa_public_key);
    Ok(public_key)
}

pub fn create_storage(eid: sgx_enclave_id_t, owner: Secp256r1PublicKey) -> SgxError {
    let public_key_str = serde_json::to_string(&owner).unwrap();
    let public_key = public_key_str.as_bytes();

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall::create_storage(
            eid,
            &mut status,
            public_key.as_ptr(),
            public_key.len() as u32,
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

//pub fn create_storage(eid: sgx_enclave_id_t, owner: Rsa3072PubKey) -> SgxError {
//    let public_key_str = serde_json::to_string(&owner).unwrap();
//    let public_key = public_key_str.as_bytes();
//
//    let mut status = sgx_status_t::SGX_SUCCESS;
//    let result = unsafe {
//        ecall::create_storage(
//            eid,
//            &mut status,
//            public_key.as_ptr(),
//            public_key.len() as u32,
//        )
//    };
//
//    if status != sgx_status_t::SGX_SUCCESS {
//        return Err(status);
//    }
//    if result != sgx_status_t::SGX_SUCCESS {
//        return Err(result);
//    }
//
//    Ok(())
//}

pub fn storage_request(eid: sgx_enclave_id_t, payload: &[u8]) -> SgxResult<Vec<u8>> {
    let mut output = [0 as u8; PAYLOAD_MAX_SIZE];
    let mut response_size: u32 = 0;
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall::storage_request(
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
