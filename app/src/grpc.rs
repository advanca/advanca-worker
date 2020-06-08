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

use futures;
use grpcio;
use protos;

use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, RwLock};

use crate::enclave;
use futures::Future;
use grpcio::{Environment, RpcContext, ServerBuilder, UnarySink};
use hex;
use log::{debug, error, info, trace};
use protos::storage::{
    EncryptedRequest, EncryptedResponse, GetRequest, GetResponse, SetRequest, SetResponse,
};
use protos::storage::{HeartbeatRequest, HeartbeatResponse};
use protos::storage_grpc::{self, Storage};

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
        format!("0x{}...", hex::encode(payload[..16].as_ref()))
    } else {
        format!("0x{}", hex::encode(payload))
    }
}

impl Storage for StorageService {
    fn heartbeat(&mut self, ctx: RpcContext, req: HeartbeatRequest, sink: UnarySink<HeartbeatResponse>) {
    }

    fn send(&mut self, ctx: RpcContext, req: EncryptedRequest, sink: UnarySink<EncryptedResponse>) {
        trace!("received encrypted request: {:?}", req.get_payload());
        debug!(
            "<EncryptedRequest> payload {:?}",
            format_payload(req.get_payload())
        );
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
            .map(move |_| trace!("replied with {:?}", res))
            .map_err(move |err| error!("failed to reply: {:?}", err));
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
            .map(move |_| trace!("replied with {:?}", res))
            .map_err(move |err| error!("failed to reply: {:?}", err));
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
            .map(move |_| trace!("replied with {:?}", res))
            .map_err(move |err| error!("failed to reply: {:?}", err));
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
    for &(ref host, port) in server.bind_addrs() {
        info!("gRPC listening on {}:{}", host, port);
    }
    exit_signal.recv().unwrap();
    info!("stopping gRPC server ...");
    let _ = server.shutdown().wait();
    info!("gRPC server stopped");
}
