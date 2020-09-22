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

use advanca_node_primitives::{AccountId, Privacy, PublicKeys, TaskSpec};

use advanca_crypto::*;
use advanca_crypto_types::*;

use substrate_subxt::{
    advanca::advanca_core::*,
    advanca::AdvancaRuntime,
    balances::{ReserveRepatriatedEvent, TransferCallExt, TransferEvent, TransferEventExt},
    balances::{ReservedEvent, UnreservedEvent},
    system::AccountStoreExt,
    Client, ClientBuilder, EventSubscription, EventsDecoder, PairSigner,
};

use codec::Decode;

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

async fn get_reserved_event(
    raw_events: &Vec<substrate_subxt::RawEvent>,
) -> Option<ReservedEvent<AdvancaRuntime>> {
    if let Some(raw_event) = raw_events
        .iter()
        .find(|raw| raw.module == "Balances" && raw.variant == "Reserved")
    {
        let reserved_event: ReservedEvent<AdvancaRuntime> =
            ReservedEvent::<AdvancaRuntime>::decode(&mut &raw_event.data[..]).unwrap();
        return Some(reserved_event);
    }
    None
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
    let (sr25519_prvkey, sr25519_pubkey) = sr25519_gen_keypair().unwrap();

    info!("generated client ec256 keypair");
    trace!("generated client ec256 keypair {:?}", prvkey.r);

    let public_keys = PublicKeys {
        secp256r1_public_key: serde_json::to_vec(&pubkey).unwrap(),
        sr25519_public_key: serde_json::to_vec(&sr25519_pubkey).unwrap(),
    };

    info!("generated client sr25519 keypair");
    trace!(
        "generated client sr25519 keypair {:?}",
        sr25519_prvkey.secret
    );

    let client_signer = PairSigner::new(client_sr25519_keypair.clone());

    // register user
    info!("registering user ...");
    let public_key = serde_json::to_vec(&pubkey).unwrap();
    info!("public_key bytes: {:?}", public_key);

    let result = api
        .register_user_and_watch(&client_signer, 1, public_keys)
        .await
        .expect("extrinsic success");
    info!("registered user (extrinsic={:?})", result.extrinsic);
    display_balance(client_account.clone(), &api).await?;

    info!("sleeping for 12 seconds...");
    async_std::task::sleep(std::time::Duration::from_secs(12)).await;

    // submit task
    info!("generating ephemeral task secp256r1 key ...");
    let (owner_task_secp256r1_prvkey, owner_task_secp256r1_pubkey) =
        secp256r1_gen_keypair().unwrap();
    debug!(
        "owner task secp256r1 prvkey: {:?}",
        owner_task_secp256r1_prvkey
    );
    debug!(
        "owner task secp256r1 pubkey: {:?}",
        owner_task_secp256r1_pubkey
    );

    info!("generating ephemeral task sr25519 key ...");
    let (owner_task_sr25519_prvkey, owner_task_sr25519_pubkey) = sr25519_gen_keypair().unwrap();
    debug!("owner task sr25519 prvkey: {:?}", owner_task_sr25519_prvkey);
    debug!("owner task sr25519 pubkey: {:?}", owner_task_sr25519_pubkey);

    let signed_task_secp256r1_pubkey = secp256r1_sign_msg(
        &prvkey,
        &serde_json::to_vec(&owner_task_secp256r1_pubkey).unwrap(),
    )
    .unwrap();
    info!(
        "signed task secp256r1 pubkey ... {:?}",
        signed_task_secp256r1_pubkey
    );

    let signed_task_sr25519_pubkey = sr25519_sign_msg(
        &sr25519_prvkey,
        &serde_json::to_vec(&owner_task_sr25519_pubkey).unwrap(),
    )
    .unwrap();
    info!(
        "signed task sr25519 pubkey ... {:?}",
        signed_task_sr25519_pubkey
    );

    info!("submitting task ...");
    let mut task_spec: TaskSpec<Privacy> = Default::default();
    task_spec.privacy = Privacy::Encryption;
    // set duration of task to infinite
    let duration = 0;
    let result = api
        .submit_task_and_watch(
            &client_signer,
            serde_json::to_vec(&signed_task_secp256r1_pubkey).unwrap(),
            serde_json::to_vec(&signed_task_sr25519_pubkey).unwrap(),
            duration,
            task_spec,
        )
        .await
        .expect("extrinsic success");
    info!("task submitted (extrinsic={:?})", result.extrinsic);
    info!("task duration: {}", duration);
    let reserved_event = get_reserved_event(&result.events).await.unwrap();
    info!("task amount reserved: {:?}", reserved_event);
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
    let enclave_secp256r1_public_key =
        serde_json::from_slice(&worker.enclave.public_keys.secp256r1_public_key).unwrap();
    debug!("enclave public key is {:?}", enclave_secp256r1_public_key);

    let signed_task_secp256r1_pubkey_bytes = task
        .signed_enclave_task_secp256r1_pubkey
        .expect("signed task pubkey should exist");
    let signed_task_secp256r1_pubkey: Secp256r1SignedMsg =
        serde_json::from_slice(&signed_task_secp256r1_pubkey_bytes).unwrap();

    // verify that the task_pubkey is untampered
    // enclave_task_pubkey is used to derive the shared secret with the enclave
    let verified =
        secp256r1_verify_msg(&enclave_secp256r1_public_key, &signed_task_secp256r1_pubkey).unwrap();
    assert_eq!(verified, true);

    // demo to show attempt to tamper pubkey to intercept communication
    let mut evil_signed_task_secp256r1_pubkey = signed_task_secp256r1_pubkey.clone();
    evil_signed_task_secp256r1_pubkey.msg[0] = 0xde;
    evil_signed_task_secp256r1_pubkey.msg[1] = 0xad;
    evil_signed_task_secp256r1_pubkey.msg[2] = 0xbe;
    evil_signed_task_secp256r1_pubkey.msg[3] = 0xef;
    let demo_verified = secp256r1_verify_msg(
        &enclave_secp256r1_public_key,
        &evil_signed_task_secp256r1_pubkey,
    )
    .unwrap();
    info!(
        "[demo] tampered signed message: {:?}",
        evil_signed_task_secp256r1_pubkey
    );
    info!("[demo] verified: {:?}", demo_verified);
    assert_eq!(demo_verified, false);

    let enclave_task_secp256r1_pubkey: Secp256r1PublicKey =
        serde_json::from_slice(&signed_task_secp256r1_pubkey.msg).unwrap();
    let kdk: Aes128Key =
        derive_kdk(&owner_task_secp256r1_prvkey, &enclave_task_secp256r1_pubkey).unwrap();
    let encrypted_worker_url = task.worker_url.expect("encrypted url should exist");
    let url_encrypted: Aes128EncryptedMsg = serde_json::from_slice(&encrypted_worker_url).unwrap();
    debug!("encrypted_url: {:?}", url_encrypted);
    debug!("key: {:?}", kdk);

    let url = aes128gcm_decrypt(&kdk, &url_encrypted).unwrap();
    let url = core::str::from_utf8(&url).unwrap();
    info!("worker url is {:?}", url);

    // talk to worker directly
    grpc::start_demo(
        &url,
        enclave_task_secp256r1_pubkey,
        owner_task_secp256r1_prvkey,
    );

    // abort the task
    info!("sleeping for 18 seconds...");
    async_std::task::sleep(std::time::Duration::from_secs(18)).await;

    info!("aborting task ...");
    let result = api
        .abort_task_and_watch(&client_signer, task_id)
        .await
        .expect("extrinsic success");
    info!("task aborted (extrinsic={:?})", result.extrinsic);
    info!("waiting for task completion!");

    let sub = api.subscribe_events().await?;
    let mut decoder = EventsDecoder::<AdvancaRuntime>::new(api.metadata().clone());
    decoder.with_advanca_core();
    let mut sub = EventSubscription::<AdvancaRuntime>::new(sub, decoder);
    loop {
        let raw = sub.next().await.unwrap().unwrap();
        if raw.module == "Balances" && raw.variant == "ReserveRepatriated" {
            let reserve_repatriate: ReserveRepatriatedEvent<AdvancaRuntime> =
                ReserveRepatriatedEvent::<AdvancaRuntime>::decode(&mut &raw.data[..]).unwrap();
            info!("task payment: {:?}", reserve_repatriate);
        }
        if raw.module == "Balances" && raw.variant == "Unreserved" {
            let unreserve: UnreservedEvent<AdvancaRuntime> =
                UnreservedEvent::<AdvancaRuntime>::decode(&mut &raw.data[..]).unwrap();
            info!("task unreserve remaining: {:?}", unreserve);
        }
        if raw.module == "AdvancaCore" && raw.variant == "TaskCompleted" {
            info!("task completed!");
            break;
        }
    }
    display_balance(client_account.clone(), &api).await?;

    Ok(())
}
