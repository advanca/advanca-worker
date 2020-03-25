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

    pub fn set(&self, key: &str, value: &str) {
        let mut req = SetRequest::new();
        req.set_key(key.into());
        req.set_value(value.into());

        trace!("SetRequest: {:?}", req);
        let res = self.storage_client.set(&req).expect("set should work");
        trace!("SetResponse: {:?}", &res);
    }

    pub fn get(&self, key: &str) -> String {
        let mut req = GetRequest::new();
        req.set_key(key.into());

        trace!("GetRequest: {:?}", &req);
        let res = self.storage_client.get(&req).expect("get should work");
        trace!("GetResponse: {:?}", &res);

        res.get_value().into()
    }

    pub fn set_secretly(&self, key: &str, value: &str) {
        let mut req = SetRequest::new();
        req.set_key(key.into());
        req.set_value(value.into());

        let mut plain_req = PlainRequest::new();
        plain_req.set_set_request(req);

        trace!("SetRequest: {:?}", &plain_req);
        let res = self.send_encrypted_request(plain_req);
        let res = res.get_set_response();
        trace!("SetResponse: {:?}", &res);
    }

    pub fn get_secretly(&self, key: &str) -> String {
        let mut req = GetRequest::new();
        req.set_key(key.into());

        let mut plain_req = PlainRequest::new();
        plain_req.set_get_request(req);

        trace!("GetRequest: {:?}", &plain_req);
        let res = self.send_encrypted_request(plain_req);
        let res = res.get_get_response();
        trace!("GetResponse: {:?}", &res);

        res.get_value().into()
    }
}

pub fn start_demo(url: &str, enclave_key: Rsa3072PubKey, client_key: Rsa3072KeyPair) {
    let client = Client::new(url, client_key, enclave_key);

    info!("accessing unencrypted storage hosted on worker ...");
    info!("set(apple=pie)");
    client.set("apple", "pie");
    thread::sleep(time::Duration::from_secs(2));
    info!("set(apple=great)");
    client.set("apple", "great");
    thread::sleep(time::Duration::from_secs(2));

    info!("get(apple)={}", client.get("apple"));
    thread::sleep(time::Duration::from_secs(2));
    info!("get(banana)={}", client.get("banana"));
    thread::sleep(time::Duration::from_secs(2));

    info!("accessing encrypted storage protected by enclave ...");
    info!("secretly set(earth=1)");
    client.set_secretly("earth", "1");
    thread::sleep(time::Duration::from_secs(2));
    info!("secretly set(moon=2)");
    client.set_secretly("moon", "2");
    thread::sleep(time::Duration::from_secs(2));

    info!("secretly get(earth)={}", client.get_secretly("earth"));
    thread::sleep(time::Duration::from_secs(2));
    info!("secretly get(sun)={}", client.get_secretly("sun"));
    thread::sleep(time::Duration::from_secs(2));
}
