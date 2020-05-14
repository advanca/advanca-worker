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

use std::str;
use std::sync::mpsc::channel;
use std::thread;

use env_logger;
use env_logger::Builder;
use hex;
use log::LevelFilter;
use log::{debug, info, trace};
use structopt::StructOpt;

use sp_core::{crypto::Pair, sr25519};
use sp_keyring::AccountKeyring;

use advanca_core::{Privacy, TaskSpec};
use advanca_runtime::AccountId;
use substrate_api::SubstrateApi;

use serde_cbor;
use sgx_types::*;

use advanca_crypto_types::*;
mod aes;
use advanca_crypto::{secp256r1_public};
use sgx_ucrypto::*;

mod grpc;

/// helper function to fund the account
fn fund_account(ws_url: &str, account: &AccountId) {
    let mut alice_api = SubstrateApi::new(ws_url);
    alice_api.set_signer(AccountKeyring::Alice.pair());
    alice_api.transfer_balance(account.to_owned(), 1_000_000_000);
}

#[derive(Debug, StructOpt)]
#[structopt(about = "advanca client usage")]
struct Opt {
    #[structopt(
        short = "w",
        long = "ws-url",
        default_value = "ws://127.0.0.1:9944",
        help = "advanca-node websocket url"
    )]
    ws_url: String,
}

fn main() {
    let opt = Opt::from_args();
    let mut builder = Builder::from_default_env();
    builder
        .default_format()
        .format_level(true)
        .format_module_path(false)
        .format_timestamp(None)
        .filter(Some("advanca_client"), LevelFilter::Debug)
        .init();

    // generate sr25519 keypair
    let (client_sr25519_keypair, _) = sr25519::Pair::generate();
    let client_account: AccountId = client_sr25519_keypair
        .public()
        .as_array_ref()
        .to_owned()
        .into();
    info!(
        "sr25519 keypair generated: {}",
        hex::encode(&client_sr25519_keypair.public())
    );

    // fund the user account
    fund_account(&opt.ws_url, &client_account);
    info!("funded account {:?}", client_account);

    // generate secp256r1 keypair for communication with worker
    let mut pubkey = sgx_ec256_public_t::default();
    let mut prvkey = sgx_ec256_private_t::default();
    let mut ecc_handle: sgx_ecc_state_handle_t = 0 as sgx_ecc_state_handle_t;

    unsafe{
    let _ = sgx_ecc256_open_context(&mut ecc_handle);
    let _ = sgx_ecc256_create_key_pair(&mut prvkey, &mut pubkey, ecc_handle);
    let _ = sgx_ecc256_close_context(ecc_handle);
    }
    info!("generated client ec256 keypair");
    trace!(
        "generated client ec256 keypair {:?}",
        prvkey.r
    );
    let client_prvkey = Secp256r1PrivateKey {
        r: prvkey.r
    };
    let client_pubkey = secp256r1_public::from_sgx_ec256_public(&pubkey);

    let mut api = SubstrateApi::new(&opt.ws_url);
    api.set_signer(client_sr25519_keypair.clone());
    info!("connected to advanca-node API");

    // register user
    info!("registering user ...");
    let public_key = serde_cbor::to_vec(&client_pubkey).unwrap();
    info!("public_key bytes: {:?}", public_key);
    // let public_key = client_rsa3072_keypair.export_pubkey().unwrap();
    //let public_key_hex = serde_json::to_string(&public_key).unwrap();
    let hash = api.register_user(1 as u128, public_key);
    info!("registered user (extrinsic={:?})", hash);

    // wait for the worker registration
    info!("waiting for worker ...");
    let worker_id = api.listen_for_worker_added();
    info!("got a new worker (id={})", worker_id);

    info!("querying worker information ...");
    let worker = api.get_worker(worker_id);
    info!("received worker information");
    let enclave_public_key = serde_cbor::from_slice(&worker.enclave.public_key).unwrap();
    debug!("enclave public key is {:?}", enclave_public_key);

    let kdk = aes::derive_session_key(&enclave_public_key, &client_prvkey);


    let (task_in, task_out) = channel();
    let handle: thread::JoinHandle<_> = thread::spawn(move || {
        let listener_api = SubstrateApi::new(&opt.ws_url);

        task_in
            .send(listener_api.listen_for_task_submitted())
            .unwrap();
    });

    // submit task
    info!("submitting task ...");
    let mut task_spec: TaskSpec<Privacy> = Default::default();
    task_spec.privacy = Privacy::Encryption;
    let hash = api.submit_task(0, task_spec);
    info!("task submitted (extrinsic={:?})", hash);

    let task_id = task_out.recv().unwrap();
    handle.join().unwrap();

    // wait for the task to be accepted
    info!("waiting for the task to be accepted ...");
    api.wait_all_task_accepted(vec![task_id]);
    info!("task accepted, moving forward");

    let task = api.get_task(task_id);

    let worker_id = task.worker.expect("There should be a worker ID");

    info!("querying worker information ...");
    let worker = api.get_worker(worker_id);
    info!("received worker information");
    let enclave_public_key = serde_cbor::from_slice(&worker.enclave.public_key).unwrap();
    debug!("enclave public key is {:?}", enclave_public_key);

    let kdk = aes::derive_session_key(&enclave_public_key, &client_prvkey);

    let url_encrypted = task.worker_url.expect("encrypted url should exist");
    debug!("encrypted_url: {:?}", url_encrypted);
    debug!("key: {:?}", kdk);
    // let url = decrypt_url_sgx_crypto(client_rsa3072_keypair, &url_encrypted);
    let url = aes::aes128_gcm_decrypt(kdk, url_encrypted);
    let url = core::str::from_utf8(&url).unwrap();
    info!("worker url is {:?}", url);

    // talk to worker directly
    grpc::start_demo(&url, enclave_public_key, client_prvkey);

    // abort the task
    info!("aborting task ...");
    let hash = api.abort_task(task_id);
    info!("task aborted (extrinsic={:?})", hash);
}
