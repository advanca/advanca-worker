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

use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use sgx_crypto_helper::RsaKeyPair;

struct Client {
    storage_client: StorageClient,
    keypair: Rsa3072KeyPair,
    server_public_key: Rsa3072PubKey,
}

impl Client {
    pub fn new(url: &str, keypair: Rsa3072KeyPair, server_public_key: Rsa3072PubKey) -> Client {
        let env = Arc::new(EnvBuilder::new().build());
        let ch = ChannelBuilder::new(env).connect(url);

        Client {
            storage_client: StorageClient::new(ch),
            keypair,
            server_public_key,
        }
    }

    pub fn send_encrypted_request(&self, plain_req: PlainRequest) -> PlainResponse {
        let mut req = EncryptedRequest::new();
        {
            let plaintext = plain_req.write_to_bytes().unwrap();
            let mut ciphertext = Vec::new();
            let ciphertext_len = self
                .server_public_key
                .encrypt_buffer(&plaintext, &mut ciphertext)
                .unwrap();
            req.set_payload((&ciphertext[..ciphertext_len]).to_vec());
        }
        trace!("encrypted req {:?}", req);
        let res = self.storage_client.send(&req).unwrap();
        {
            let ciphertext = res.get_payload();
            let mut plaintext = Vec::new();
            trace!("response payload {:?}", ciphertext);
            trace!("decryption key {:?}", self.keypair.clone());
            let plaintext_len = self
                .keypair
                .decrypt_buffer(&ciphertext, &mut plaintext)
                .expect("decryption failed");
            parse_from_bytes::<PlainResponse>(&(&plaintext[..plaintext_len]).to_vec())
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

pub fn start_demo(url: &str, enclave_key: Rsa3072PubKey, client_key: Rsa3072KeyPair) {
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
