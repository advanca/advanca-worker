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
use log::{debug, error, info, trace};
use protos::storage::{
    EncryptedRequest, EncryptedResponse, GetRequest, GetResponse, SetRequest, SetResponse,
    Msg
};
use protos::storage::Msg_MsgType as MsgType;
use protos::storage_grpc::{self, Storage};

use std::fs;
use std::thread;

use core::mem::size_of;


use futures::stream::Stream;
use futures::sink::Sink;

use grpcio::*;

use advanca_crypto_ctypes::*;


use hex;
use sgx_ra;






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
    fn remote_attest (
        &mut self,
        _ctx: RpcContext,
        msg_in: RequestStream<Msg>,
        msg_out: DuplexSink<Msg>,) {
        // we won't be using the grpcio polling thread,
        // instead we'll use our own thread and block
        // on the messages, making it a single, bi-direction
        // protocol exchange between the attestee and us.
        thread::spawn(move || {
            // msg_in  : blocking iterator
            // msg_out : blocking stream
            let mut msg_in = msg_in.wait();
            let mut msg_out = msg_out.wait();

            // initialize the session
            let aas_prvkey_der = fs::read("sp_prv_pk8.der").unwrap();
            let spid_hex = fs::read_to_string("sp_ias_spid.txt").unwrap();
            let spid_hex = spid_hex.trim();
            let spid = hex::decode(spid_hex).unwrap();
            let ias_apikey_str = fs::read_to_string("sp_ias_apikey.txt").unwrap();
            let is_dev = true;
            let mut session = sgx_ra::sp_init_ra(&aas_prvkey_der, &spid, &ias_apikey_str, is_dev);

            // get msg0 and msg1 from the attestee
            let msg0 = msg_in.next().unwrap().unwrap();
            assert_eq!(MsgType::SGX_RA_MSG0, msg0.get_msg_type());

            if sgx_ra::sp_proc_ra_msg0(msg0.get_msg_bytes()) {
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG0_REPLY);
                msg.set_msg_bytes(1_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();
            } else {
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG0_REPLY);
                msg.set_msg_bytes(0_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();
            }

            let msg1 = msg_in.next().unwrap().unwrap();
            assert_eq!(MsgType::SGX_RA_MSG1, msg1.get_msg_type());
            let msg2_bytes = sgx_ra::sp_proc_ra_msg1(msg1.get_msg_bytes(), &mut session);

            let mut msg = Msg::new();
            msg.set_msg_type(MsgType::SGX_RA_MSG2);
            msg.set_msg_bytes(msg2_bytes);
            let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();

            // at this point we have derived the secret keys and we'll wait for the attestee to
            // send us msg3, after which we will forward to ias to verify the sgx platform.
            let msg3 = msg_in.next().unwrap().unwrap();
            let ias = sgx_ra::sp_proc_ra_msg3(msg3.get_msg_bytes(), &mut session);
            let quote = ias.get_isv_enclave_quote_body();
            let is_secure = ias.is_enclave_secure(true);
            let is_debug = quote.is_enclave_debug();
            println!("is_secure: {:?}", &is_secure);
            println!("is_debug : {:?}", &is_debug);
            println!("is_init  : {:?}", quote.is_enclave_init());
            println!("mrenclave: {:02x?}", quote.get_mr_enclave());
            println!("mrsigner : {:02x?}", quote.get_mr_signer());

            // verify mrenclave, mrsigner, is_secure, is_debug
            // TODO: we'll ignore debug flag for eval purposes.
            // let is_verified = is_secure && !is_debug;
            let is_verified = is_secure;

            if is_verified {
                // sends the ok message and recv the request
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG3_REPLY);
                msg.set_msg_bytes(1_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();

                let msg_reg_request = msg_in.next().unwrap().unwrap();
                assert_eq!(MsgType::AAS_RA_REG_REQUEST, msg_reg_request.get_msg_type());
                let reg_request_bytes = msg_reg_request.get_msg_bytes();
                assert_eq!(reg_request_bytes.len(), size_of::<CAasRegRequest>());
                let p_reg_request = unsafe{*(reg_request_bytes.as_ptr() as *const CAasRegRequest)};
                let reg_report = sgx_ra::sp_proc_aas_reg_request(&p_reg_request, &session).unwrap();
                let msg_bytes = serde_cbor::to_vec(&reg_report).unwrap();
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::AAS_RA_REG_REPORT);
                msg.set_msg_bytes(msg_bytes);
                let _ = msg_out.send((msg.to_owned(), WriteFlags::default())).unwrap();
            } else {
                // sends the nok message and terminate
                let mut msg = Msg::new();
                msg.set_msg_type(MsgType::SGX_RA_MSG3_REPLY);
                msg.set_msg_bytes(0_u32.to_le_bytes().to_vec());
                let _ = msg_out.send((msg.to_owned(),WriteFlags::default())).unwrap();
            }
        });
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
