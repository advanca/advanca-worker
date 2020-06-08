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

use sgx_types::*;
use std::collections::HashMap;
use std::default::Default;
use std::string::{String, ToString};

use serde_big_array::big_array;
use serde_derive::*;
use serde_json;
use serde_big_array::big_array;

big_array! { BigArray; }

big_array! { BigArray; }

use log::trace;
use oram::SqrtOram;
use protos::storage::*;
use sgx_tstd::io::ErrorKind;
use sgx_tstd::untrusted::fs::remove_file;

use crate::constants::SEALED_STORAGE_FILE;
use crate::io;

pub const ORAM_BLOCK_SIZE: usize = 1024;
//pub const ORAM_SIZE: usize = 256;
pub const ORAM_SIZE: usize = 8;

#[derive(Serialize, Deserialize)]
struct Storage {
    #[serde(with = "BigArray")]
    owner: [u8;64],
    backend: HashMap<String, String>,
}

impl Default for Storage {
    fn default() -> Storage {
        Storage {
            owner: [0;64],
            backend: HashMap::default(),
        }
    }
}

pub fn create_sealed_storage(owner: [u8;64]) -> SgxResult<sgx_status_t> {
    let storage = Storage {
        owner,
        ..Default::default()
    };
    let storage_json = serde_json::to_string(&storage).unwrap();
    if let Err(e) = remove_file(SEALED_STORAGE_FILE) {
        if e.kind() == ErrorKind::NotFound {
            trace!("{} not found, nothing removed", SEALED_STORAGE_FILE);
        } else {
            println!(
                "[ENCLAVE ERROR] error when removing file {}: {}",
                SEALED_STORAGE_FILE, e
            );
        }
    } else {
        println!("[ENCLAVE INFO] removed old file {}", SEALED_STORAGE_FILE);
    }
    io::seal(storage_json.as_bytes(), SEALED_STORAGE_FILE)
}

fn unseal_storage() -> SgxResult<Storage> {
    let bytes = io::unseal(SEALED_STORAGE_FILE)?;
    let storage_json = std::str::from_utf8(&bytes).unwrap();
    let storage: Storage = serde_json::from_str(&storage_json).unwrap();
    Ok(storage)
}

fn seal_storage(storage: &Storage) -> SgxError {
    let storage_json = serde_json::to_string(storage).unwrap();
    io::seal(storage_json.as_bytes(), SEALED_STORAGE_FILE)?;
    Ok(())
}

pub fn storage_request(plain_request: PlainRequest) -> SgxResult<PlainResponse> {
    let mut plain_response = PlainResponse::new();
    let mut storage = unseal_storage()?;

    let mut oram = SqrtOram::open("oram", ORAM_SIZE, ORAM_BLOCK_SIZE);

    if plain_request.has_set_request() {
        let set_req = plain_request.get_set_request();
        let mut set_res = SetResponse::new();
        match plain_request.get_privacy() {
            Privacy::ENCRYPTION => {
                match storage
                    .backend
                    .insert(set_req.get_key().into(), set_req.get_value().into())
                {
                    None => set_res.set_message("new key and value created".into()),
                    Some(_) => set_res.set_message("new value updated".into()),
                }
            }
            Privacy::SQRTORAM => {
                let index: u32 = set_req.get_key().parse().unwrap();
                let value = set_req.get_value().as_bytes().to_vec();
                oram.put(index, value);
                // TODO: handle put failure
                set_res.set_message("key inserted".into());
            }
        }

        plain_response.set_set_response(set_res);
    } else if plain_request.has_get_request() {
        let get_req = plain_request.get_get_request();

        let mut get_res = GetResponse::new();

        match plain_request.get_privacy() {
            Privacy::ENCRYPTION => match storage.backend.get(get_req.get_key()) {
                Some(k) => {
                    get_res.set_value(k.clone());
                    get_res.set_message("key exists, value returned".into());
                }
                None => get_res.set_message("key not found".into()),
            },
            Privacy::SQRTORAM => {
                let index: u32 = get_req.get_key().parse().unwrap();
                if let Some(value) = oram.get(index) {
                    get_res.set_value(std::str::from_utf8(&value).unwrap().to_string());
                    get_res.set_message("key exists, value returned".into());
                } else {
                    get_res.set_message("key not found".into());
                }
            }
        }

        plain_response.set_get_response(get_res);
    }
    seal_storage(&storage)?;

    Ok(plain_response)
}
