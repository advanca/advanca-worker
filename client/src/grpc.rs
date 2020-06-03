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

use std::sync::Arc;
use std::thread;
use std::time;

use grpcio;
use grpcio::{ChannelBuilder, EnvBuilder};
use log::{info, trace};

use protobuf::parse_from_bytes;
use protobuf::Message;
use protos::storage::*;
use protos::storage_grpc::StorageClient;

use serde::{Deserialize, Serialize};

use advanca_crypto_types::*;
use advanca_crypto::*;

struct Client {
    storage_client: StorageClient,
    keypair: Secp256r1PrivateKey,
    server_public_key: Secp256r1PublicKey,
}

impl Client {
    pub fn new(url: &str, keypair: Secp256r1PrivateKey, server_public_key: Secp256r1PublicKey) -> Client {
        let env = Arc::new(EnvBuilder::new().build());
        let ch = ChannelBuilder::new(env).connect(url);

        Client {
            storage_client: StorageClient::new(ch),
            keypair,
            server_public_key,
        }
    }

    pub fn send_encrypted_request(&self, plain_req: PlainRequest) -> PlainResponse {
        // TODO: fix this hack... currently we are just deriving the key where-ever we need
        let key = derive_kdk(&self.keypair, &self.server_public_key).unwrap();

        let mut req = EncryptedRequest::new();
        {
            let plaintext = plain_req.write_to_bytes().unwrap();
            let encrypted_msg = aes128gcm_encrypt(&key, &plaintext).unwrap();
            req.set_payload(serde_cbor::to_vec(&encrypted_msg).unwrap());
        }
        trace!("encrypted req {:?}", req);
        let res = self.storage_client.send(&req).unwrap();
        {
            let ciphertext = res.get_payload();
            let encrypted_msg_bytes = ciphertext.to_vec();
            let encrypted_msg = serde_cbor::from_slice(&encrypted_msg_bytes).unwrap();
            trace!("response payload {:?}", ciphertext);
            trace!("decryption key {:?}", key);
            let plaintext = aes128gcm_decrypt(&key, &encrypted_msg).unwrap();
            parse_from_bytes::<PlainResponse>(&plaintext)
                .expect("parsing failed")
        }
    }

    #[allow(dead_code)]
    pub fn set(&self, key: &str, value: &str) {
        let mut req = SetRequest::new();
        req.set_key(key.into());
        req.set_value(value.into());

        trace!("SetRequest: {:?}", req);
        let res = self.storage_client.set(&req).expect("set should work");
        trace!("SetResponse: {:?}", &res);
    }

    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> String {
        let mut req = GetRequest::new();
        req.set_key(key.into());

        trace!("GetRequest: {:?}", &req);
        let res = self.storage_client.get(&req).expect("get should work");
        trace!("GetResponse: {:?}", &res);

        res.get_value().into()
    }

    #[allow(dead_code)]
    pub fn set_secretly(&self, key: &str, value: &str, oram: bool) {
        let mut req = SetRequest::new();
        req.set_key(key.into());
        req.set_value(value.into());

        let mut plain_req = PlainRequest::new();
        plain_req.set_set_request(req);

        if oram {
            plain_req.set_privacy(Privacy::SQRTORAM);
        }

        trace!("SetRequest: {:?}", &plain_req);
        let res = self.send_encrypted_request(plain_req);
        let res = res.get_set_response();
        trace!("SetResponse: {:?}", &res);
    }

    pub fn get_secretly(&self, key: &str, oram: bool) -> String {
        let mut req = GetRequest::new();
        req.set_key(key.into());

        let mut plain_req = PlainRequest::new();
        plain_req.set_get_request(req);

        if oram {
            plain_req.set_privacy(Privacy::SQRTORAM);
        }

        trace!("GetRequest: {:?}", &plain_req);
        let res = self.send_encrypted_request(plain_req);
        let res = res.get_get_response();
        trace!("GetResponse: {:?}", &res);

        res.get_value().into()
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Patient {
    id: &'static str,
    name: &'static str,
    birthdate: &'static str,
    phone: &'static str,
}

impl Patient {
    fn new(
        id: &'static str,
        name: &'static str,
        birthdate: &'static str,
        phone: &'static str,
    ) -> Self {
        Patient {
            id,
            name,
            birthdate,
            phone,
        }
    }
}

pub fn start_demo(url: &str, enclave_key: Secp256r1PublicKey, client_key: Secp256r1PrivateKey) {
    let client = Client::new(url, client_key, enclave_key);

    let thomas = Patient::new("0", "Thomas", "1900-01-01", "11111111");
    let miranda = Patient::new("1", "Miranda", "1900-02-02", "22222222");

    info!("accessing patient information in ORAM storage");

    info!("put Thomas's info: {:?}", thomas);
    client.set_secretly(thomas.id, &serde_json::to_string(&thomas).unwrap(), true);
    thread::sleep(time::Duration::from_secs(2));

    info!("put Miranda's info: {:?}", miranda);
    client.set_secretly(miranda.id, &serde_json::to_string(&miranda).unwrap(), true);
    thread::sleep(time::Duration::from_secs(2));

    info!(
        "get Thomas's info: {}",
        client.get_secretly(thomas.id, true)
    );
    thread::sleep(time::Duration::from_secs(2));

    info!(
        "get Miranda's info: {}",
        client.get_secretly(miranda.id, true)
    );
    thread::sleep(time::Duration::from_secs(2));
}
