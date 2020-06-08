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

use std::convert::TryFrom;
use std::str;
use std::sync::mpsc;
use std::thread;

use env_logger;
use env_logger::Builder;
use log::LevelFilter;
use log::{debug, error, info};
use structopt::StructOpt;

use sp_core::{crypto::Pair, sr25519};
use sp_keyring::AccountKeyring;

use substrate_api::SubstrateApi;

use advanca_core::Enclave;
use advanca_runtime::AccountId;

mod enclave;
mod grpc;

use sgx_types::*;
// use sgx_urts::*;

use std::mem::{size_of};

mod aas_teaclave_ecall;
use aas_teaclave_ecall::*;

mod trusted_key_exchange_ecall;
use trusted_key_exchange_ecall::*;


use std::sync::Arc;
use grpcio::*;
use aas_protos::aas::Msg;
use aas_protos::aas::Msg_MsgType as MsgType;
use aas_protos::aas_grpc::AasServerClient;

use futures::{Sink, Stream};

use advanca_crypto_types::*;
use advanca_crypto::*;

use advanca_macros::handle_ecall;

use sgx_types::*;
// use sgx_urts::*;

use std::mem::size_of;

mod aas_teaclave_ecall;
use aas_teaclave_ecall::*;

mod trusted_key_exchange_ecall;
use trusted_key_exchange_ecall::*;

use aas_protos::aas::Msg;
use aas_protos::aas::Msg_MsgType as MsgType;
use aas_protos::aas_grpc::AasServerClient;
use grpcio::*;
use std::sync::Arc;

use futures::{Sink, Stream};

use advanca_crypto::*;
use advanca_crypto_ctypes::CAasRegRequest;
use advanca_crypto_types::*;

/// helper function to fund the account
fn fund_account(ws_url: &str, account: &AccountId) {
    let mut bob_api = SubstrateApi::new(ws_url);
    bob_api.set_signer(AccountKeyring::Bob.pair());
    bob_api.transfer_balance(account.to_owned(), 1_000_000_000);
}

#[derive(Debug, StructOpt)]
#[structopt(about = "advanca worker usage")]
struct Opt {
    #[structopt(
        short = "w",
        long = "ws-url",
        default_value = "ws://127.0.0.1:9944",
        help = "advanca-node websocket url"
    )]
    ws_url: String,
    #[structopt(
        short = "g",
        long = "grpc-external-url",
        default_value = "127.0.0.1:8135",
        help = "set advanca-worker external address and port"
    )]
    grpc_url: String,
    #[structopt(
        long = "aas-url",
        default_value = "127.0.0.1:11800",
        help = "set advanca-attestation-service address and port"
    )]
    aas_url: String,
}

fn aas_remote_attest(
    aas_url: &str,
    eid: sgx_enclave_id_t,
    ra_context: sgx_ra_context_t,
) -> AasRegReport {
    let mut retval = sgx_status_t::SGX_SUCCESS;

    // We'll try to connect to the service provider
    let env = Arc::new(Environment::new(2));
    let channel = ChannelBuilder::new(env).connect(aas_url);
    let client = AasServerClient::new(channel);
    let (tx, rx) = client.remote_attest().unwrap();
    // convert to blocking communication
    let mut tx = tx.wait();
    let mut rx = rx.wait();

    let mut extended_epid_gid: u32 = 10;
    let sgx_return = unsafe { sgx_get_extended_epid_group_id(&mut extended_epid_gid) };
    debug!("sgx_get_extended_epid_group_id: {}", sgx_return);
    debug!("epid_gid  : {}", extended_epid_gid);

    // MSG0 is p_extended_epid_group_id
    // isv_app -> service_provider
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG0);
    msg.set_msg_bytes(extended_epid_gid.to_le_bytes().to_vec());
    tx.send((msg, WriteFlags::default())).unwrap();
    info!("[worker]---[msg0]------------->[aas]                      [ias]");

    let msg0_reply = rx.next().unwrap().unwrap();
    assert_eq!(msg0_reply.get_msg_type(), MsgType::SGX_RA_MSG0_REPLY);
    if msg0_reply.get_msg_bytes() == 0_u32.to_le_bytes() {
        panic!("Oops! AAS rejected msg0!");
    }
    info!("[worker]<--[msg0_reply]--------[aas]                      [ias]");

    // MSG1 contains g_a (public ephermeral key ECDH for App) and gid (EPID Group ID - For SigRL)
    let mut p_msg1_buf = vec![0; size_of::<sgx_ra_msg1_t>()];
    let sgx_return = unsafe {
        sgx_ra_get_msg1(
            ra_context,
            eid,
            sgx_ra_get_ga,
            p_msg1_buf.as_mut_ptr() as *mut sgx_ra_msg1_t,
        )
    };
    info!("sgx_ra_get_msg1: {}", sgx_return);
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG1);
    msg.set_msg_bytes(p_msg1_buf);
    tx.send((msg, WriteFlags::default())).unwrap();
    info!("[worker]---[msg1]------------->[aas]                      [ias]");

    // MSG2 contains g_b (public ephemeral ECDH key for SP), SPID, quote_type,
    // KDF (key derivation function), signed (gb, ga) using SP's non-ephemeral P256 key, MAC, SigRL
    let msg2 = rx.next().unwrap().unwrap();
    info!("[worker]<--[msg2]--------------[aas]                      [ias]");

    let p_msg2_ptr = msg2.get_msg_bytes().as_ptr() as *const sgx_ra_msg2_t;
    let msg2_size = msg2.get_msg_bytes().len();
    // prepare pointer to recv p_msg3 and its size.
    let mut p_msg3_ptr: *mut sgx_ra_msg3_t = 0 as *mut sgx_ra_msg3_t;
    let mut msg3_size = 0_u32;
    let sgx_return = unsafe {
        sgx_ra_proc_msg2(
            ra_context,
            eid,
            sgx_ra_proc_msg2_trusted,
            sgx_ra_get_msg3_trusted,
            p_msg2_ptr,
            msg2_size as u32,
            &mut p_msg3_ptr,
            &mut msg3_size,
        )
    };
    debug!("sgx_ra_proc_msg2: {}", sgx_return);
    debug!("msg3_size: {}", msg3_size);

    // send msg3 to attestation server
    let msg3_vec = unsafe {
        core::slice::from_raw_parts(p_msg3_ptr as *const u8, msg3_size as usize).to_vec()
    };
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG3);
    msg.set_msg_bytes(msg3_vec);
    tx.send((msg, WriteFlags::default())).unwrap();
    info!("[worker]---[msg3]------------->[aas]                      [ias]");

    let msg3_reply = rx.next().unwrap().unwrap();
    info!("[worker]<--[attest_result]-----[aas]                      [ias]");

    assert_eq!(msg3_reply.get_msg_type(), MsgType::SGX_RA_MSG3_REPLY);
    debug!("msg3 mac: {:02x?}", unsafe { (*p_msg3_ptr).mac });

    if msg3_reply.get_msg_bytes() == 1u32.to_le_bytes() {
        // aas accepted our attestation, we'll prepare the request
        let mut aas_request = CAasRegRequest::default();
        let mut worker_pubkey = sgx_ec256_public_t::default();
        let _ = unsafe { gen_worker_ec256_pubkey(eid, &mut retval, &mut worker_pubkey) };
        let _ = unsafe { gen_worker_reg_request(eid, &mut retval, ra_context, &mut aas_request) };
        let p_aas_request = &aas_request as *const CAasRegRequest as *const u8;
        let aas_request_byte_slice =
            unsafe { core::slice::from_raw_parts(p_aas_request, size_of::<CAasRegRequest>()) };

        let mut msg = Msg::new();
        msg.set_msg_type(MsgType::AAS_RA_REG_REQUEST);
        msg.set_msg_bytes(aas_request_byte_slice.to_vec());
        tx.send((msg, WriteFlags::default())).unwrap();
        info!("[worker]---[aas_reg_request]-->[aas]                      [ias]");

        let msg_aas_report = rx.next().unwrap().unwrap();
        info!("[worker]<--[aas_reg_report]----[aas]                      [ias]");

        assert_eq!(msg_aas_report.get_msg_type(), MsgType::AAS_RA_REG_REPORT);
        let aas_report_bytes = msg_aas_report.get_msg_bytes();
        let aas_report: AasRegReport = serde_cbor::from_slice(aas_report_bytes).unwrap();
        // 04:1a:4f:ea:0d:04:bd:ed:7d:c1:43:ee:74:cb:8e:
        // 56:9e:6e:49:1c:89:bc:d6:5c:34:8f:8a:5b:40:5f:
        // 79:53:e3:89:7d:0f:0c:bc:cf:f0:45:ce:c9:a9:1d:
        // 39:9c:cc:3e:09:ee:b0:2a:b6:d2:8d:dd:67:9b:b4:
        // bb:5c:68:98:9c
        let srv_pubkey = Secp256r1PublicKey {
            gx: [
                227, 83, 121, 95, 64, 91, 138, 143, 52, 92, 214, 188, 137, 28, 73, 110, 158, 86,
                142, 203, 116, 238, 67, 193, 125, 237, 189, 4, 13, 234, 79, 26,
            ],
            gy: [
                156, 152, 104, 92, 187, 180, 155, 103, 221, 141, 210, 182, 42, 176, 238, 9, 62,
                204, 156, 57, 29, 169, 201, 206, 69, 240, 207, 188, 12, 15, 125, 137,
            ],
        };
        let report_verify = aas_utils::verify_aas_reg_report(&aas_report, &srv_pubkey);
        debug!("report verified: {:?}", report_verify);
        debug!("{:?}", srv_pubkey);
        if report_verify {
            return aas_report;
        } else {
            panic!("Report mac verification failed!\nReport might be modified!");
        }
    } else {
        panic!("AAS rejected our attestation. >.<");
    }
}

fn aas_remote_attest(eid: sgx_enclave_id_t, ra_context: sgx_ra_context_t) -> AasRegReport {
    // We'll try to connect to the service provider
    let env = Arc::new(Environment::new(2));
    let channel = ChannelBuilder::new(env).connect("127.0.0.1:12345");
    let client = AasServerClient::new(channel);
    let (tx,rx) = client.remote_attest().unwrap();
    // convert to blocking communication
    let mut tx = tx.wait();
    let mut rx = rx.wait();

    let mut extended_epid_gid: u32 = 10;
    let sgx_return = unsafe { sgx_get_extended_epid_group_id(&mut extended_epid_gid) };
    debug!("sgx_get_extended_epid_group_id: {}", sgx_return);
    debug!("epid_gid  : {}", extended_epid_gid);

    // MSG0 is p_extended_epid_group_id 
    // isv_app -> service_provider
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG0);
    msg.set_msg_bytes(extended_epid_gid.to_le_bytes().to_vec());
    tx.send((msg,WriteFlags::default())).unwrap();
    info!("[worker]---[msg0]------------->[aas]                      [ias]");

    let msg0_reply = rx.next().unwrap().unwrap();
    assert_eq!(msg0_reply.get_msg_type(), MsgType::SGX_RA_MSG0_REPLY);
    if msg0_reply.get_msg_bytes() == 0_u32.to_le_bytes() {
        panic!("Oops! AAS rejected msg0!");
    }
    info!("[worker]<--[msg0_reply]--------[aas]                      [ias]");

    // MSG1 contains g_a (public ephermeral key ECDH for App) and gid (EPID Group ID - For SigRL)
    let mut p_msg1_buf = vec![0; size_of::<sgx_ra_msg1_t>()];
    let sgx_return = unsafe { sgx_ra_get_msg1(ra_context, eid, sgx_ra_get_ga, p_msg1_buf.as_mut_ptr() as *mut sgx_ra_msg1_t) };
    info!("sgx_ra_get_msg1: {}", sgx_return);
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG1);
    msg.set_msg_bytes(p_msg1_buf);
    tx.send((msg,WriteFlags::default())).unwrap();
    info!("[worker]---[msg1]------------->[aas]                      [ias]");


    // MSG2 contains g_b (public ephemeral ECDH key for SP), SPID, quote_type,
    // KDF (key derivation function), signed (gb, ga) using SP's non-ephemeral P256 key, MAC, SigRL
    let msg2 = rx.next().unwrap().unwrap();
    info!("[worker]<--[msg2]--------------[aas]                      [ias]");

    let p_msg2_ptr = msg2.get_msg_bytes().as_ptr() as *const sgx_ra_msg2_t;
    let msg2_size = msg2.get_msg_bytes().len();
    // prepare pointer to recv p_msg3 and its size.
    let mut p_msg3_ptr: *mut sgx_ra_msg3_t = 0 as *mut sgx_ra_msg3_t;
    let mut msg3_size = 0_u32;
    let sgx_return = unsafe {sgx_ra_proc_msg2(ra_context, eid, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, p_msg2_ptr, msg2_size as u32 , &mut p_msg3_ptr, &mut msg3_size)};
    debug!("sgx_ra_proc_msg2: {}", sgx_return);
    debug!("msg3_size: {}", msg3_size);

    // send msg3 to attestation server
    let msg3_vec = unsafe {core::slice::from_raw_parts(p_msg3_ptr as *const u8, msg3_size as usize).to_vec()};
    let mut msg = Msg::new();
    msg.set_msg_type(MsgType::SGX_RA_MSG3);
    msg.set_msg_bytes(msg3_vec);
    tx.send((msg,WriteFlags::default())).unwrap();
    info!("[worker]---[msg3]------------->[aas]                      [ias]");

    let msg3_reply = rx.next().unwrap().unwrap();
    info!("[worker]<--[attest_result]-----[aas]                      [ias]");

    assert_eq!(msg3_reply.get_msg_type(), MsgType::SGX_RA_MSG3_REPLY);
    debug!("msg3 mac: {:02x?}", unsafe{(*p_msg3_ptr).mac});

    if msg3_reply.get_msg_bytes() == 1u32.to_le_bytes() {
        // aas accepted our attestation, we'll prepare the request
        let mut buf = [0_u8;4096];
        let mut buf_size: usize = buf.len();
        let _ = unsafe {handle_ecall!(eid, gen_worker_ec256_pubkey()).unwrap()};
        let _ = unsafe {handle_ecall!(eid, gen_worker_reg_request(buf.as_mut_ptr(), &mut buf_size, ra_context)).unwrap()};

        let mut msg = Msg::new();
        msg.set_msg_type(MsgType::AAS_RA_REG_REQUEST);
        msg.set_msg_bytes(buf[..buf_size].to_vec());
        tx.send((msg, WriteFlags::default())).unwrap();
        info!("[worker]---[aas_reg_request]-->[aas]                      [ias]");

        let msg_aas_report = rx.next().unwrap().unwrap();
        info!("[worker]<--[aas_reg_report]----[aas]                      [ias]");

        assert_eq!(msg_aas_report.get_msg_type(), MsgType::AAS_RA_REG_REPORT);
        let aas_report_bytes = msg_aas_report.get_msg_bytes();
        let aas_report: AasRegReport = serde_cbor::from_slice(aas_report_bytes).unwrap();
        // 04:1a:4f:ea:0d:04:bd:ed:7d:c1:43:ee:74:cb:8e:
        // 56:9e:6e:49:1c:89:bc:d6:5c:34:8f:8a:5b:40:5f:
        // 79:53:e3:89:7d:0f:0c:bc:cf:f0:45:ce:c9:a9:1d:
        // 39:9c:cc:3e:09:ee:b0:2a:b6:d2:8d:dd:67:9b:b4:
        // bb:5c:68:98:9c
        let srv_pubkey = Secp256r1PublicKey{
            gx:[227, 83, 121, 95, 64, 91, 138, 143, 52, 92, 214, 188, 137, 28, 73, 110, 158, 86, 142, 203, 116, 238, 67, 193, 125, 237, 189, 4, 13, 234, 79, 26],
            gy:[156, 152, 104, 92, 187, 180, 155, 103, 221, 141, 210, 182, 42, 176, 238, 9, 62, 204, 156, 57, 29, 169, 201, 206, 69, 240, 207, 188, 12, 15, 125, 137],
        };
        let report_verify = aas_verify_reg_report(&srv_pubkey, &aas_report).unwrap();
        debug!("report verified: {:?}", report_verify);
        debug!("{:?}", srv_pubkey);
        if report_verify {
            return  aas_report;
        } else {
            panic!("Report mac verification failed!\nReport might be modified!");
        }
    } else {
        panic!("AAS rejected our attestation. >.<");
    }
}

fn main() {
    let opt = Opt::from_args();
    let mut builder = Builder::from_default_env();
    builder
        .default_format()
        .format_level(true)
        .format_module_path(false)
        .format_timestamp(None)
        .filter(Some("advanca_worker"), LevelFilter::Debug)
        .init();

    let grpc_port = opt
        .grpc_url
        .split(":")
        .last()
        .expect("extract grpc port")
        .parse::<u16>()
        .expect("parse port number");

    let e = enclave::init().expect("enclave initialization");
    let eid = e.geteid();

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut ra_context: sgx_ra_context_t = 10;

    let sgx_return = unsafe {enclave_init_ra(eid, &mut retval, 0, &mut ra_context)};
    info!("enclave_init_ra: {}", sgx_return);
    info!("ra_context: {}", ra_context);

    let aas_report = aas_remote_attest(eid, ra_context);
    info!("Remote attestation complete!");
    info!("AAS Report: {:?}", aas_report);

    // TODO: clean this up when we figure out how to terminate when remote_attest fails
    // currently if aas_remote_attest returns, we know the report is valid and attestation
    // is performed and valid.
    let mut buf = [0_u8;4096];
    let mut buf_size: usize = buf.len();
    let _ = unsafe{handle_ecall!(eid, get_worker_ec256_pubkey(buf.as_mut_ptr(), &mut buf_size)).unwrap()};
    let worker_pubkey: Secp256r1PublicKey = serde_cbor::from_slice(&buf[..buf_size]).unwrap();
    info!("ec256 pubkey generated {:?}", worker_pubkey);

    let (worker_keypair, _) = sr25519::Pair::generate();
    let worker_account: AccountId = worker_keypair.public().as_array_ref().to_owned().into();
    info!("sr25519 keypair generated {:?}", worker_keypair.public());

    // inject funds into worker account
    fund_account(&opt.ws_url, &worker_account);
    debug!("funded account {:?}", worker_account);

    let mut api = SubstrateApi::new(&opt.ws_url);
    api.set_signer(worker_keypair);

    // get the keys from enclave
    let sr25519_public_key = sr25519::Public::try_from(
        &enclave::sr25519_public_key(e.geteid()).expect("enclave sr25519 public key")[..],
    )
    .unwrap(); //.try_into().unwrap();

    let enclave = Enclave::<AccountId> {
        account_id: sr25519_public_key.as_array_ref().to_owned().into(),
        public_key: serde_cbor::to_vec(&worker_pubkey).unwrap(),
        attestation: serde_cbor::to_vec(&aas_report).unwrap(),
    };

    info!("registering worker ...");
    let hash = api.register_worker(10, enclave);
    info!("registered worker (extrinsic={:?})", hash);

    // listen for new task
    info!("listening for new task ...");
    let task_id = api.listen_for_task_submitted();
    info!("received a task (id={:?})", task_id.clone());

    // find out the owner of the task (i.e. user)
    info!("querying task information ...");
    let task = api.get_task(task_id);
    info!("received task information {:?}", &task);
    let owner = task.owner;

    // start grpc server, preparing for accepting the task
    let (tx, rx) = mpsc::channel();
    let handle: thread::JoinHandle<_> = thread::spawn(move || {
        info!("starting grpc server ...");
        grpc::start_grpc_server(grpc_port, e, rx);
    });

    // encrypt url with user's public key
    info!("querying user information ...");
    let user = api.get_user(owner.clone());
    info!("received user information (id={})", owner.clone());
    info!("public_key bytes: {:?}", user.public_key);
    let user_pubkey: Secp256r1PublicKey = serde_cbor::from_slice(&user.public_key).unwrap();
    let _ = unsafe {handle_ecall!(eid, accept_task(task_id.as_ptr(), user.public_key.as_ptr(), user.public_key.len())).unwrap()};
    debug!("user public key is {:?}", user_pubkey);
    let msg = opt.grpc_url.as_bytes();
    debug!("url: {:?}", opt.grpc_url);
    debug!("msg: {:?}", msg);
    buf_size = buf.len();
    let _ = unsafe{handle_ecall!(eid, encrypt_msg(buf.as_mut_ptr(), &mut buf_size, task_id.as_ptr(), msg.as_ptr(), msg.len())).unwrap()};
    let url_encrypted: Aes128EncryptedMsg = serde_cbor::from_slice(&buf[..buf_size]).unwrap();
    debug!("msg len: {:?}", msg.len());
    debug!("ivcipher len: {:?}", buf_size);
    debug!("url_encrypted: {:?}", url_encrypted);

    // accept task
    info!("initializing storage for user {:?} ...", owner);
    if let Err(e) = enclave::create_storage(eid, user_pubkey) {
        error!("failed to initialize storage {}", e);
        return;
    }
    info!(
        "accpeting task (id={}) with encrypted url {:?} ...",
        &task_id,
        url_encrypted,
    );
    let hash = api.accept_task(task_id, serde_cbor::to_vec(&url_encrypted).unwrap());
    info!("accepted task (extrinsic={:?})", hash);

    info!("waiting for task termination by user ...");
    api.wait_all_task_aborted(vec![task_id]);
    info!("task aborted");

    let sgx_return = unsafe{enclave_ra_close(eid, &mut retval, ra_context)};
    info!("enclave_ra_close: {}", sgx_return);
    info!("freeing ra_context: {}", ra_context);

    // send exiting signal to gRPC server
    tx.send(()).unwrap();

    handle
        .join()
        .expect("Couldn't join on the associated thread");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        env_logger::builder().is_test(true).try_init().unwrap();
    }

    #[test]
    fn url_encryption_sgx_crypto() {
        init();

        let url = "127.0.0.1:5443";
        let keypair = Rsa3072KeyPair::new().unwrap();

        let encrypted = encrypt_url_sgx_crypto(url, &keypair.export_pubkey().unwrap());

        let mut decrypted = Vec::new();

        keypair.decrypt_buffer(&encrypted, &mut decrypted);

        let url_decrypted = str::from_utf8(&decrypted).unwrap();

        assert_eq!(url, url_decrypted);
    }

    #[test]
    fn url_encryption() {
        init();

        let url = "127.0.0.1:5443";
        let keypair = Rsa::generate(3072).unwrap();

        let public_key = Rsa::from_public_components(
            keypair.n().to_owned().unwrap(),
            keypair.e().to_owned().unwrap(),
        )
        .expect("rsa public key");

        let encrypted = encrypt_url(url, public_key.clone());

        let mut buf = vec![0; public_key.size() as usize];
        let len = keypair
            .private_decrypt(&encrypted, &mut buf, Padding::PKCS1)
            .expect("url decryption");
        buf.split_off(len);

        let decrypted_url = str::from_utf8(&buf).expect("decode url into string");

        assert_eq!(url, decrypted_url);
    }
}
