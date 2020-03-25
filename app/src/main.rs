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

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use substrate_api::SubstrateApi;

use advanca_core::Enclave;
use advanca_runtime::AccountId;

mod enclave;
mod grpc;

use grpc::format_payload;

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
        default_value = "127.0.0.1:12345",
        help = "set advanca-worker external address and port"
    )]
    grpc_url: String,
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

    let (worker_keypair, _) = sr25519::Pair::generate();
    let worker_account: AccountId = worker_keypair.public().as_array_ref().to_owned().into();
    info!("sr25519 keypair generated {:?}", worker_keypair.public());

    // inject funds into worker account
    fund_account(&opt.ws_url, &worker_account);
    debug!("funded account {:?}", worker_account);

    let mut api = SubstrateApi::new(&opt.ws_url);
    api.set_signer(worker_keypair);

    // get the keys from enclave
    let rsa3072_public_key =
        enclave::rsa3072_public_key(e.geteid()).expect("enclave rsa3072 public key");
    let sr25519_public_key = sr25519::Public::try_from(
        &enclave::sr25519_public_key(e.geteid()).expect("enclave sr25519 public key")[..],
    )
    .unwrap(); //.try_into().unwrap();

    let enclave = Enclave::<AccountId> {
        account_id: sr25519_public_key.as_array_ref().to_owned().into(),
        public_key: rsa3072_public_key,
        attestation: vec![], // TODO: get this attestation field from enclave after remote attestation is implemented
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
    let public_key_hex = str::from_utf8(&user.public_key).unwrap();
    let public_key: Rsa3072PubKey = serde_json::from_str(public_key_hex).unwrap();
    debug!("user public key is {:?}", public_key);
    let url_encrypted = encrypt_url_sgx_crypto(&opt.grpc_url, &public_key);

    // accept task
    info!("initializing storage for user {:?} ...", owner);
    if let Err(e) = enclave::create_storage(eid, public_key) {
        error!("failed to initialize storage {}", e);
        return;
    }
    info!(
        "accpeting task (id={}) with encrypted url {} ...",
        &task_id,
        format_payload(&url_encrypted.clone())
    );
    let hash = api.accept_task(task_id, url_encrypted);
    info!("accepted task (extrinsic={:?})", hash);

    info!("waiting for task termination by user ...");
    api.wait_all_task_aborted(vec![task_id]);
    info!("task aborted");

    // send exiting signal to gRPC server
    tx.send(()).unwrap();

    handle
        .join()
        .expect("Couldn't join on the associated thread");
}

fn encrypt_url_sgx_crypto(url: &str, public_key: &Rsa3072PubKey) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    public_key
        .encrypt_buffer(url.as_bytes(), &mut ciphertext)
        .unwrap();
    ciphertext
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
