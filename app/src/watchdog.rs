use jsonrpsee::{client::Subscription, Client};
use log::{debug, info, trace};
use sp_runtime::generic;
use sp_runtime::traits::BlakeTwo256;
use std::sync::{Arc, Mutex};

use crate::enclave::heartbeat_challenge;
use aas_protos_std::aas::aas::*;
use advanca_crypto::*;
use advanca_crypto_types::*;
use primitive_types::H256;
use sgx_types::*;
use substrate_api::SubstrateApi;
use worker_protos_std::storage::storage::*;

use std::collections::HashSet;
use hex;

// Defining the Header from sp_runtime here instead of using
// the defined type from node. Lessen compilation time.
// To be replaced when types are separated from advanca-node.
pub type Header = generic::Header<u32, BlakeTwo256>;

// public key for Advanca Attestation Service
const AAS_PUB_KEY: Secp256r1PublicKey = Secp256r1PublicKey {
    gx: [
        0xe3, 0x53, 0x79, 0x5f, 0x40, 0x5b, 0x8a, 0x8f, 0x34, 0x5c, 0xd6, 0xbc, 0x89, 0x1c, 0x49,
        0x6e, 0x9e, 0x56, 0x8e, 0xcb, 0x74, 0xee, 0x43, 0xc1, 0x7d, 0xed, 0xbd, 0x04, 0x0d, 0xea,
        0x4f, 0x1a,
    ],
    gy: [
        0x9c, 0x98, 0x68, 0x5c, 0xbb, 0xb4, 0x9b, 0x67, 0xdd, 0x8d, 0xd2, 0xb6, 0x2a, 0xb0, 0xee,
        0x09, 0x3e, 0xcc, 0x9c, 0x39, 0x1d, 0xa9, 0xc9, 0xce, 0x45, 0xf0, 0xcf, 0xbc, 0x0c, 0x0f,
        0x7d, 0x89,
    ],
};

pub fn print_task_stats (task_id: H256, api: Arc<Mutex<SubstrateApi>>) {
    // Print information about the completed task
    info!("reading task stats from chain ...");
    debug!("preparing to access task stats: {:?}", task_id);
    debug!("get task information");
    let task = api.lock().unwrap().get_task(task_id);
    trace!("{:?}", task);
    debug!("get worker information");
    let worker_account_id = task.worker.unwrap();
    let worker_info = api.lock().unwrap().get_worker(worker_account_id);
    trace!("{:?}", worker_info);
    debug!("verifying worker's attestation report");
    let worker_attestation_report = serde_cbor::from_slice(&worker_info.enclave.attestation).unwrap();
    assert_eq!(true, aas_verify_reg_report(&AAS_PUB_KEY, &worker_attestation_report).unwrap());
    debug!("get worker's attested pubkey");
    let worker_pubkey: Secp256r1PublicKey = worker_attestation_report.worker_pubkey;
    debug!("verifying worker's task pubkey");
    let signed_worker_task_pubkey = serde_cbor::from_slice(&task.signed_worker_task_pubkey.unwrap()).unwrap();
    assert_eq!(true, secp256r1_verify_msg(&worker_pubkey, &signed_worker_task_pubkey).unwrap());
    let worker_task_pubkey: Secp256r1PublicKey = serde_cbor::from_slice(&signed_worker_task_pubkey.msg).unwrap();
    debug!("iterating over the evidences ...");
    let mut verified_evidence = 0;
    let mut alive_blocks = HashSet::new();
    let mut storage_in = 0;
    let mut storage_out = 0;
    let mut storage_size = 0;
    let mut data_in = 0;
    let mut data_out = 0;
    for evidence_bytes in task.worker_heartbeat_evidence {
        let signed_timestamp: Secp256r1SignedMsg =
            serde_cbor::from_slice(&evidence_bytes).unwrap();
        trace!("verifying aas timestamp...");
        assert_eq!(true, secp256r1_verify_msg(&AAS_PUB_KEY, &signed_timestamp).unwrap());
        let timestamp: AasTimestamp = serde_cbor::from_slice(&signed_timestamp.msg).unwrap();
        trace!("verifying signed evidence ...");
        let signed_evidence: Secp256r1SignedMsg =
            serde_cbor::from_slice(&timestamp.data).unwrap();
        assert_eq!(true, secp256r1_verify_msg(&worker_task_pubkey, &signed_evidence).unwrap());
        let evidence: AliveEvidence = serde_cbor::from_slice(&signed_evidence.msg).unwrap();
        trace!("Evidence: {:?}", evidence);
        alive_blocks.insert(evidence.block_hash.clone());
        storage_in = evidence.storage_in;
        storage_out = evidence.storage_out;
        storage_size = evidence.storage_size;
        data_in = evidence.data_in;
        data_out = evidence.data_out;
        verified_evidence += 1;
    }
    info!("{:=^80}", "Accounting Information");
    info!("Task ID: {:?}", task_id);
    info!("Total verified evidences: {}", verified_evidence);
    info!("{:-^80}", "Blocks Alive Information");
    let total_blocks_alive = alive_blocks.len();
    for block_hash in alive_blocks {
        info!("Block Hash: {:#?}", hex::encode(block_hash));
    }
    info!("Total blocks alive: {}", total_blocks_alive);
    info!("{:-^80}", "Storage Information");
    info!("Storage in   : {}", storage_in);
    info!("Storage out  : {}", storage_out);
    info!("Storage size : {}", storage_size);
    info!("{:-^80}", "Data Information");
    info!("Data in   : {}", data_in);
    info!("Data out  : {}", data_out);
    info!("{:=^80}", "");
}


pub fn watchdog_loop(
    task_id: [u8; 32],
    eid: sgx_enclave_id_t,
    uri: &str,
    is_done: Arc<Mutex<bool>>,
    aas_client: Arc<Mutex<AasServerClient>>,
    api: Arc<Mutex<SubstrateApi>>,
) {
    async_std::task::block_on(async move {
        let mut alive_evidence = Vec::<Vec<u8>>::new();
        let transport = jsonrpsee::transport::ws::WsTransportClient::new(uri)
            .await
            .unwrap();
        let raw_client = jsonrpsee::raw::RawClient::new(transport);
        let client: Client = raw_client.into();
        let mut sub: Subscription<Header> = client
            .subscribe(
                "chain_subscribeFinalizedHeads",
                jsonrpsee::common::Params::None,
                "chain_unsubscribeFinalizedHeads",
            )
            .await
            .unwrap();

        while let ev = sub.next().await {
            let block_hash = ev.hash();
            trace!("block_hash: {:?}", block_hash.as_bytes());
            let mut heartbeat_req = HeartbeatRequest::new();
            heartbeat_req.task_id = task_id.to_vec();
            heartbeat_req.block_hash = block_hash.as_bytes().to_vec();
            let heartbeat_response = heartbeat_challenge(eid, heartbeat_req);
            let mut timestamp_request = TimestampRequest::new();
            timestamp_request.data = heartbeat_response.heartbeat_sig.to_owned();
            // connect to aas to get a timestamp for heartbeat_response
            let timestamp_response = aas_client
                .lock()
                .unwrap()
                .timestamp(&timestamp_request)
                .unwrap();
            let timestamp: Secp256r1SignedMsg =
                serde_cbor::from_slice(&timestamp_response.signed_data).unwrap();
            trace!("timestamp response: {:?}", timestamp);
            // save to vec, prepare to post to chain when watching ends
            alive_evidence.push(serde_cbor::to_vec(&timestamp).unwrap());
            if *is_done.lock().unwrap() {
                break;
            }
        }
        let task_id = H256::from(&task_id);
        let evidence_extrinsic = api
            .lock()
            .unwrap()
            .submit_task_evidence(task_id, alive_evidence);
        debug!("evidence extrinsic: {:?}", evidence_extrinsic);
        print_task_stats(task_id, api);
    });
}
