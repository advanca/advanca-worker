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
use env_logger;
use hex;
use log::{debug, info, trace};
use structopt::StructOpt;

use sp_core::{crypto::Pair, sr25519};
use sp_keyring::AccountKeyring;

use advanca_node_primitives::{AccountId, Privacy, TaskSpec};

use serde_cbor;

use advanca_crypto::*;
use advanca_crypto_types::*;

use substrate_subxt::{
    advanca::advanca_core::*,
    advanca::AdvancaRuntime,
    balances::{TransferCallExt, TransferEvent, TransferEventExt},
    system::AccountStoreExt,
    Client, ClientBuilder, EventSubscription, EventsDecoder, PairSigner,
};

mod grpc;

/// helper function to fund the account
async fn fund_account(api: &Client<AdvancaRuntime>, account: &AccountId) {
    // Alice has initial balances so using it to fund 'account'
    let alice = PairSigner::new(AccountKeyring::Alice.pair());
    trace!("funding account {:?}", account);
    let result = api
        .transfer_and_watch(&alice, &account, 1_000_000_000_000 as u128)
        .await
        .expect("extrinsic success");

    trace!(
        "confirmed extrinsic '{:?}' at block '{:?}'",
        result.extrinsic,
        result.block
    );
    let event = result.transfer().expect("decode event").expect("has event");
    let expected_event = TransferEvent {
        from: alice.signer().public().as_array_ref().to_owned().into(),
        to: account.clone(),
        amount: 1_000_000_000_000,
    };
    assert_eq!(expected_event, event, "got expected event");
    trace!("fund_account done");
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

async fn display_balance(
    account_id: AccountId,
    api: &Client<AdvancaRuntime>,
) -> Result<(), Box<dyn std::error::Error>> {
    let accountdata = api.account(&account_id, None).await?.data;
    info!("{:=^80}", "Client Balance Information");
    info!("Free        : {:?}", accountdata.free);
    info!("Reserved    : {:?}", accountdata.reserved);
    info!("Misc Frozen : {:?}", accountdata.misc_frozen);
    info!("Fee Frozen  : {:?}", accountdata.fee_frozen);
    info!("{:=^80}", "");
    Ok(())
}

async fn wait_for_event<E, P, R>(
    api: &Client<R>,
    predicate: P,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: Fn(&E) -> bool,
    R: AdvancaCore + substrate_subxt::Runtime,
    E: substrate_subxt::Event<R> + std::fmt::Debug,
{
    let sub = api.subscribe_events().await?;
    let mut decoder = EventsDecoder::<R>::new(api.metadata().clone());
    decoder.with_advanca_core();

    let mut event_sub = EventSubscription::new(sub, decoder);
    event_sub.filter_event::<E>();

    while let Some(result) = event_sub.next().await {
        let event = E::decode(&mut &result?.data[..])?;
        trace!("Received event {:?}", event);
        if predicate(&event) {
            trace!("Found the matched event");
            return Ok(());
        }
    }
    Err("Cannot find the matching event".into())
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    env_logger::from_env(env_logger::Env::default().default_filter_or("advanca_client=debug"))
        .init();

    let api = ClientBuilder::<AdvancaRuntime>::new()
        .set_url(&opt.ws_url)
        .build()
        .await?;
    info!("connected to advanca-node API");
    trace!("API Metadata:\n{}", api.metadata().pretty());

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
    fund_account(&api, &client_account).await;
    info!("funded account {:?}", client_account);

    // generate secp256r1 keypair for communication with worker
    let (prvkey, pubkey) = secp256r1_gen_keypair().unwrap();

    info!("generated client ec256 keypair");
    trace!("generated client ec256 keypair {:?}", prvkey.r);

    let client_signer = PairSigner::new(client_sr25519_keypair.clone());

    // register user
    info!("registering user ...");
    let public_key = serde_cbor::to_vec(&pubkey).unwrap();
    info!("public_key bytes: {:?}", public_key);

    let result = api
        .register_user_and_watch(&client_signer, 1, public_key)
        .await
        .expect("extrinsic success");
    info!("registered user (extrinsic={:?})", result.extrinsic);
    display_balance(client_account.clone(), &api).await?;

    // submit task
    info!("generating ephemeral task key ...");
    let (owner_task_prvkey, owner_task_pubkey) = secp256r1_gen_keypair().unwrap();
    debug!("owner task prvkey: {:?}", owner_task_prvkey);
    debug!("owner task pubkey: {:?}", owner_task_pubkey);
    let signed_task_pubkey =
        secp256r1_sign_msg(&prvkey, &serde_cbor::to_vec(&owner_task_pubkey).unwrap()).unwrap();
    info!("signed task pubkey ... {:?}", signed_task_pubkey);
    info!("submitting task ...");
    let mut task_spec: TaskSpec<Privacy> = Default::default();
    task_spec.privacy = Privacy::Encryption;
    let result = api
        .submit_task_and_watch(
            &client_signer,
            serde_cbor::to_vec(&signed_task_pubkey).unwrap(),
            0,
            task_spec,
        )
        .await
        .expect("extrinsic success");
    info!("task submitted (extrinsic={:?})", result.extrinsic);
    display_balance(client_account.clone(), &api).await?;

    let task_id = result
        .task_submitted()
        .expect("decode event")
        .expect("has event")
        .task_id;
    info!("task_id is {:?}", task_id);

    info!("waiting for the task to be accepted ...");
    wait_for_event(&api, |e: &TaskAcceptedEvent<AdvancaRuntime>| {
        e.task_id == task_id.clone()
    })
    .await?;
    info!("task accepted, moving forward");

    let task = api.tasks(task_id, None).await?;
    let worker_id = task.worker.expect("There should be a worker ID");
    info!("got a new worker (id={})", worker_id);

    info!("querying worker information ...");
    let worker = api.workers(worker_id, None).await?;
    info!("received worker information");
    let enclave_public_key = serde_cbor::from_slice(&worker.enclave.public_key).unwrap();
    debug!("enclave public key is {:?}", enclave_public_key);

    let signed_task_pubkey_bytes = task
        .signed_worker_task_pubkey
        .expect("signed task pubkey should exist");
    let signed_task_pubkey: Secp256r1SignedMsg =
        serde_cbor::from_slice(&signed_task_pubkey_bytes).unwrap();

    // verify that the task_pubkey is untampered
    let verified = secp256r1_verify_msg(&enclave_public_key, &signed_task_pubkey).unwrap();
    assert_eq!(verified, true);
    let worker_task_pubkey: Secp256r1PublicKey =
        serde_cbor::from_slice(&signed_task_pubkey.msg).unwrap();
    let kdk: Aes128Key = derive_kdk(&owner_task_prvkey, &worker_task_pubkey).unwrap();
    let encrypted_worker_url = task.worker_url.expect("encrypted url should exist");
    let url_encrypted: Aes128EncryptedMsg = serde_cbor::from_slice(&encrypted_worker_url).unwrap();
    debug!("encrypted_url: {:?}", url_encrypted);
    debug!("key: {:?}", kdk);

    let url = aes128gcm_decrypt(&kdk, &url_encrypted).unwrap();
    let url = core::str::from_utf8(&url).unwrap();
    info!("worker url is {:?}", url);

    // talk to worker directly
    grpc::start_demo(&url, worker_task_pubkey, owner_task_prvkey);

    // abort the task
    info!("sleeping for 12 seconds...");
    async_std::task::sleep(std::time::Duration::from_secs(12)).await;
    info!("aborting task ...");
    let result = api
        .abort_task_and_watch(&client_signer, task_id)
        .await
        .expect("extrinsic success");
    info!("task aborted (extrinsic={:?})", result.extrinsic);
    info!("sleeping for 18 seconds...");
    async_std::task::sleep(std::time::Duration::from_secs(18)).await;
    display_balance(client_account.clone(), &api).await?;

    Ok(())
}
