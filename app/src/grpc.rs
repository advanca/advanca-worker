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

use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, RwLock};

use crate::enclave;
use async_std::task;
use futures::prelude::*;
use grpcio::{Environment, RpcContext, ServerBuilder, UnarySink};
use log::{debug, error, info, trace};

use worker_protos_std::storage::storage::{
    EncryptedRequest, EncryptedResponse, GetRequest, GetResponse, HeartbeatRequest,
    HeartbeatResponse, SetRequest, SetResponse,
};
use worker_protos_std::storage::storage_grpc::{self, Storage};

use rand::Rng;

use advanca_crypto::*;
use advanca_crypto_types::*;

#[derive(Clone)]
struct StorageService {
    database: Arc<RwLock<HashMap<String, String>>>,
    enclave: Arc<Mutex<enclave::SgxEnclave>>,
}

impl StorageService {
    pub fn new(e: enclave::SgxEnclave) -> Self {
        StorageService {
            database: Default::default(),
            enclave: Arc::new(Mutex::new(e)),
        }
    }
}

pub fn format_payload(payload: &[u8]) -> String {
    if payload.len() > 16 {
        format!("0x{}...", hex::encode(&payload[..16]))
    } else {
        format!("0x{}", hex::encode(payload))
    }
}

impl Storage for StorageService {
    fn demo_compute(
        &mut self,
        ctx: RpcContext,
        req: EncryptedRequest,
        sink: UnarySink<EncryptedResponse>,
    ) {
        let eid = self.enclave.lock().unwrap().geteid();
        trace!("received encrypted request: {:?}", req.get_payload());
        debug!(
            "<EncryptedRequest> payload {:?}",
            format_payload(req.get_payload())
        );
        let output_payload = enclave::demo_compute_rpc(eid, req.get_payload());

        trace!("output_payload from enclave = {:?}", &output_payload);
        let mut res = EncryptedResponse::new();
        res.set_payload(output_payload.to_vec());
        debug!(
            "<EncryptedResponse> payload {:?}",
            format_payload(res.get_payload())
        );
        let f = sink
            .success(res.clone())
            .map_err(move |err| error!("failed to reply: {:?}", err))
            .map(move |_| trace!("replied with {:?}", res));
        ctx.spawn(f)
    }

    fn heartbeat(
        &mut self,
        ctx: RpcContext,
        req: HeartbeatRequest,
        sink: UnarySink<HeartbeatResponse>,
    ) {
        let eid = self.enclave.lock().unwrap().geteid();
        let response = enclave::heartbeat_challenge(eid, req);
        let f = sink
            .success(response.clone())
            .map_err(move |err| error!("failed to reply: {:?}", err))
            .map(move |_| trace!("replied with {:?}", response));
        ctx.spawn(f)
    }

    fn send(&mut self, ctx: RpcContext, req: EncryptedRequest, sink: UnarySink<EncryptedResponse>) {
        trace!("received encrypted request: {:?}", req.get_payload());
        debug!(
            "<EncryptedRequest> payload {:?}",
            format_payload(req.get_payload())
        );
        let encrypted_msg: Aes128EncryptedMsg = serde_json::from_slice(&req.get_payload()).unwrap();
        let random_key = Aes128Key {
            key: rand::thread_rng().gen::<[u8; 16]>(),
        };
        info!("[demo] encrypted request: {:?}", encrypted_msg);
        info!("[demo] random key: {:?}", random_key);
        info!("[demo] attempting to decrypt using random key...");
        let attempted_decryption = aes128gcm_decrypt(&random_key, &encrypted_msg);
        info!("[demo] {:?}", attempted_decryption);

        let output_payload = enclave::storage_request(
            self.enclave.clone().lock().unwrap().geteid(),
            req.get_payload(),
        )
        .expect("sgx storage request");

        trace!("output_payload from enclave = {:?}", &output_payload);
        let mut res = EncryptedResponse::new();
        res.set_payload(output_payload.to_vec());
        debug!(
            "<EncryptedResponse> payload {:?}",
            format_payload(res.get_payload())
        );
        let f = sink
            .success(res.clone())
            .map_err(move |err| error!("failed to reply: {:?}", err))
            .map(move |_| trace!("replied with {:?}", res));
        ctx.spawn(f)
    }

    fn get(&mut self, ctx: RpcContext, req: GetRequest, sink: UnarySink<GetResponse>) {
        trace!("received get request: {:?}", req);
        debug!("<GetRequest> {:?}", req);
        let mut res = GetResponse::new();
        match self.database.clone().read().unwrap().get(req.get_key()) {
            None => res.set_message("Key not found".into()),
            Some(v) => {
                res.set_message("Key found".into());
                res.set_value(v.clone())
            }
        };
        debug!("<GetResponse> {:?}", res);
        let f = sink
            .success(res.clone())
            .map_err(move |err| error!("failed to reply: {:?}", err))
            .map(move |_| trace!("replied with {:?}", res));
        ctx.spawn(f)
    }

    fn set(&mut self, ctx: RpcContext, req: SetRequest, sink: UnarySink<SetResponse>) {
        trace!("received set request: {:?}", req);
        debug!("<SetRequest> {:?}", req);
        let mut res = SetResponse::new();
        let find_value = self
            .database
            .clone()
            .write()
            .unwrap()
            .insert(req.get_key().into(), req.get_value().into());
        res.set_message(match &find_value {
            None => "Key not found, new key created".into(),
            Some(_) => "Key updated".into(),
        });
        trace!("update database {:?}", &self.database);
        debug!("<SetResponse> {:?}", res);
        let f = sink
            .success(res.clone())
            .map_err(move |err| error!("failed to reply: {:?}", err))
            .map(move |_| trace!("replied with {:?}", res));
        ctx.spawn(f);
    }
}

pub fn start_grpc_server(port: u16, e: enclave::SgxEnclave, exit_signal: Receiver<()>) {
    let env = Arc::new(Environment::new(1));
    let ss = StorageService::new(e);
    let service = storage_grpc::create_storage(ss);
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind("0.0.0.0", port)
        .build()
        .unwrap();
    server.start();
    for (host, port) in server.bind_addrs() {
        info!("gRPC listening on {}:{}", host, port);
    }
    exit_signal.recv().unwrap();
    info!("stopping gRPC server ...");
    task::block_on(async move {
        let _ = server.shutdown().await;
    });
    info!("gRPC server stopped");
}
