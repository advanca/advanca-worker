use jsonrpsee::{client::Subscription, Client};
use log::{debug, info, trace};
use sp_runtime::generic;
use sp_runtime::traits::BlakeTwo256;
use std::sync::{Arc, Mutex};

use crate::enclave::heartbeat_challenge;
use aas_protos_std::aas::aas::*;
use advanca_crypto_types::*;
use primitive_types::H256;
use sgx_types::*;
use substrate_api::SubstrateApi;
use worker_protos_std::storage::storage::*;

// Defining the Header from sp_runtime here instead of using
// the defined type from node. Lessen compilation time.
// To be replaced when types are separated from advanca-node.
pub type Header = generic::Header<u32, BlakeTwo256>;

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

        // find out the owner of the task (i.e. user)
        let task = api.lock().unwrap().get_task(task_id);
        info!("iterating over the evidences ...");
        for evidence_bytes in task.worker_heartbeat_evidence {
            let signed_timestamp: Secp256r1SignedMsg =
                serde_cbor::from_slice(&evidence_bytes).unwrap();
            let timestamp: AasTimestamp = serde_cbor::from_slice(&signed_timestamp.msg).unwrap();
            let signed_evidence: Secp256r1SignedMsg =
                serde_cbor::from_slice(&timestamp.data).unwrap();
            let evidence: AliveEvidence = serde_cbor::from_slice(&signed_evidence.msg).unwrap();
            info!("Evidence: {:?}", evidence);
        }
    });
}
