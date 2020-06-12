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

mod events;

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::sync::mpsc::channel;

use codec::{Decode, Encode};
use log::{error, info, trace};

use advanca_core::{
    self, Ciphertext, Duration, Enclave, Privacy, Task, TaskSpec, TaskStatus, User, Worker,
};
use advanca_runtime::{AccountId, Balance, Hash};
use sp_core::{sr25519, Pair};
use substrate_api_client::{
    node_metadata::Metadata,
    utils::{hexstr_to_u256, hexstr_to_vec},
    Api,
};

pub use substrate_api_client::compose_extrinsic;

//TODO: use TaskId<T> from advanca_core
pub type TaskId = Hash;

/// The wrapper of substrate-api-client
pub struct SubstrateApi(Api<sr25519::Pair>);

impl SubstrateApi {
    /// Create an API without signer
    pub fn new(ws_url: &str) -> SubstrateApi {
        SubstrateApi(Api::new(ws_url.into()))
    }

    /// Make a copy of the inner API type
    pub fn clone_api(&self) -> Api<sr25519::Pair> {
        self.0.clone()
    }

    /// Set signer
    pub fn set_signer(&mut self, signer: sr25519::Pair) {
        let api = self.0.clone();
        self.0 = api.set_signer(signer);
    }

    /// Return genesis hash
    pub fn genesis_hash(&self) -> Hash {
        self.0.get_genesis_hash()
    }

    /// Return runtime spec version
    pub fn spec_version(&self) -> u32 {
        self.0.get_spec_version()
    }

    /// Helper function to get the runtime metadata
    pub fn print_metadata(&self) {
        let meta = Metadata::try_from(self.0.get_metadata()).unwrap();

        meta.print_overview();
        meta.print_modules_with_calls();
        meta.print_modules_with_events();

        println!(
            "Metadata:\n {}",
            Metadata::pretty_format(&self.0.get_metadata()).unwrap()
        );
    }

    fn get_storage(&self, prefix: &str, key: &str, param_encoded: Option<Vec<u8>>) -> String {
        trace!(
            "calling get_storage(prefix={}, key={}, param={:?})",
            prefix,
            key,
            param_encoded
        );
        let result = self.0.get_storage(prefix, key, param_encoded).unwrap();
        trace!("received encoded storage value {}", result);
        result
    }

    /// send the encoded extrinsic out
    ///
    /// the `extrinsic_encoded` is an encoded string with prefix "0x"
    pub fn send_extrinsic(&self, extrinsic_encoded: String) -> Hash {
        trace!(
            "sending composed extrinsic: {:64?} (len={})",
            extrinsic_encoded,
            &extrinsic_encoded.len()
        );

        let hash = self.0.send_extrinsic(extrinsic_encoded).unwrap();
        trace!("received extrinsic hash {:?}", hash);
        hash
    }

    /// Get the nonce of the spcecified account
    pub fn get_nonce(&self, account: &AccountId) -> u32 {
        let hex_str = self.get_storage("System", "AccountNonce", Some(account.encode()));
        let nonce = hexstr_to_u256(hex_str).unwrap();
        trace!("received nonce {:?}", &nonce.low_u32());
        nonce.low_u32()
    }

    pub fn get_worker(&self, id: AccountId) -> Worker<AccountId> {
        let hex_str = self.get_storage("AdvancaCore", "Workers", Some(id.encode()));
        let worker_encoded = hexstr_to_vec(hex_str).unwrap();
        trace!("worker encoded {:?}", hex::encode(&worker_encoded));
        let worker = Decode::decode(&mut worker_encoded.as_slice()).unwrap();
        trace!("worker {:?}", worker);
        worker
    }

    pub fn get_task(
        &self,
        id: TaskId,
    ) -> Task<TaskId, AccountId, Duration, TaskSpec<Privacy>, TaskStatus, Ciphertext> {
        let hex_str = self.get_storage("AdvancaCore", "Tasks", Some(id.encode()));
        let task_encoded = hexstr_to_vec(hex_str).unwrap();
        trace!("task encoded {:?}", hex::encode(&task_encoded));
        let task = Decode::decode(&mut task_encoded.as_slice()).unwrap();
        trace!("task {:?}", task);
        task
    }

    pub fn get_user(&self, id: AccountId) -> User<AccountId> {
        let hex_str = self.get_storage("AdvancaCore", "Users", Some(id.encode()));
        let user_encoded = hexstr_to_vec(hex_str).unwrap();
        trace!("user encoded {:?}", hex::encode(&user_encoded));
        let user = Decode::decode(&mut user_encoded.as_slice()).unwrap();
        trace!("user {:?}", user);
        user
    }

    pub fn get_unscheduled_tasks(&self) -> Vec<TaskId> {
        let hex_str = self.get_storage("AdvancaCore", "UnscheduledTasks", None);
        let unscheduled_encoded = hexstr_to_vec(hex_str).unwrap();
        trace!(
            "unscheduled_tasks encoded {:?}",
            hex::encode(&unscheduled_encoded)
        );
        let unscheduled_tasks: Vec<Hash> =
            Decode::decode(&mut unscheduled_encoded.as_slice()).unwrap();
        trace!("unscheduled_task {:?}", unscheduled_tasks);
        unscheduled_tasks
    }

    pub fn transfer_balance(&self, to: AccountId, amount: Balance) -> Hash {
        let xt = self.0.balance_transfer(to.into(), amount);
        trace!("composed extrinsic: {:?}", xt);
        self.send_extrinsic(xt.hex_encode())
    }

    pub fn register_user(&self, deposit: Balance, public_key: Vec<u8>) -> Hash {
        let extrinsic = compose_extrinsic!(
            self.0.clone(),
            "AdvancaCore",
            "register_user",
            deposit,
            public_key
        );
        trace!("composed extrinsic {:?}", &extrinsic);
        self.send_extrinsic(extrinsic.hex_encode())
    }

    pub fn register_worker(&self, deposit: Balance, enclave: Enclave<AccountId>) -> Hash {
        let extrinsic = compose_extrinsic!(
            self.0.clone(),
            "AdvancaCore",
            "register_worker",
            deposit,
            enclave
        );
        trace!("composed extrinsic {:?}", &extrinsic);
        self.send_extrinsic(extrinsic.hex_encode())
    }

    pub fn submit_task(
        &self,
        signed_user_task_pubkey: Vec<u8>,
        lease: Duration,
        task_spec: TaskSpec<Privacy>,
    ) -> Hash {
        let extrinsic = compose_extrinsic!(
            self.0.clone(),
            "AdvancaCore",
            "submit_task",
            signed_user_task_pubkey,
            lease,
            task_spec
        );
        trace!("composed extrinsic {:?}", &extrinsic);
        self.send_extrinsic(extrinsic.hex_encode())
    }

    pub fn accept_task(
        &self,
        task_id: TaskId,
        signed_eph_pubkey: Vec<u8>,
        url: Ciphertext,
    ) -> Hash {
        let extrinsic = compose_extrinsic!(
            self.0.clone(),
            "AdvancaCore",
            "accept_task",
            task_id,
            signed_eph_pubkey,
            url
        );
        trace!("composed extrinsic {:?}", extrinsic);
        self.send_extrinsic(extrinsic.hex_encode())
    }

    pub fn update_task(&self, task_id: TaskId, task_spec: TaskSpec<Privacy>) -> Hash {
        let extrinsic = compose_extrinsic!(
            self.0.clone(),
            "AdvancaCore",
            "update_task",
            task_id,
            task_spec
        );
        trace!("composed extrinsic {:?}", extrinsic);
        self.send_extrinsic(extrinsic.hex_encode())
    }

    pub fn abort_task(&self, task_id: TaskId) -> Hash {
        let extrinsic = compose_extrinsic!(self.0.clone(), "AdvancaCore", "abort_task", task_id);
        trace!("composed extrinsic: {:?}", extrinsic);
        self.send_extrinsic(extrinsic.hex_encode())
    }

    /// Listen for event WorkerAdded once
    ///
    /// Block the current thread and return the worker acount received
    pub fn listen_for_worker_added(&self) -> AccountId {
        let (events_in, events_out) = channel();
        self.0.subscribe_events(events_in.clone());
        trace!("waiting for WorkedAdded");
        let args: events::WorkerAdded = self
            .0
            .wait_for_event("AdvancaCore", "WorkerAdded", &events_out)
            .unwrap()
            .unwrap();

        let id = args.account_id.clone();
        trace!("received WorkerAdded: {:?}", args);
        id
    }

    /// Listen for event TaskSubmitted once
    ///
    /// Block the current thread and return the task id received
    pub fn listen_for_task_submitted(&self) -> TaskId {
        let api = &self.0;
        let (events_in, events_out) = channel();
        api.subscribe_events(events_in.clone());
        trace!("waiting for TaskSubmitted");
        let args: events::TaskSubmitted = api
            .wait_for_event("AdvancaCore", "TaskSubmitted", &events_out)
            .unwrap()
            .unwrap();

        let id = args.task_id.clone();
        trace!("received TaskSubmitted: {:?}", args);
        return id;
    }

    /// Wait until all the specified tasks are accepted
    ///
    /// Block the current thread
    pub fn wait_all_task_accepted(&self, task_ids: Vec<TaskId>) {
        self.wait_all_task_on_condition::<events::TaskAccepted>(task_ids);
    }

    /// Wait until all the specified tasks are aborted
    ///
    /// Block the current thread
    pub fn wait_all_task_aborted(&self, task_ids: Vec<TaskId>) {
        self.wait_all_task_on_condition::<events::TaskAborted>(task_ids);
    }

    /// Internal helper function for all wait_all_task_* functions
    fn wait_all_task_on_condition<T>(&self, task_ids: Vec<TaskId>)
    where
        T: events::Event,
    {
        let mut received: HashMap<TaskId, bool> =
            task_ids.iter().map(|i| (i.clone(), false)).collect();
        let expected_ids: HashSet<TaskId> = HashSet::from_iter(task_ids);
        let mut count = 0;
        // get the event name (e.g., TaskAccepted) from struct type name (e.g., struct TaskAccepted)
        let variant = std::any::type_name::<T>().split("::").last().unwrap();

        let (events_in, events_out) = channel();

        let api = &self.0;

        api.subscribe_events(events_in.clone());

        loop {
            let args: T = api
                .wait_for_event("AdvancaCore", variant, &events_out)
                .unwrap()
                .unwrap();

            if expected_ids.contains(&args.task_id()) {
                if let Some(seen) = received.get_mut(&args.task_id()) {
                    if !*seen {
                        trace!("hit one task with id {:?}", &args.task_id());
                        *seen = true;
                        count += 1;
                        if count == expected_ids.len() {
                            trace!("all task received, returning");
                            return;
                        }
                    } else {
                        error!(
                            "received event {} with same id(={}) twice, something is wrong",
                            variant,
                            &args.task_id()
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use sp_core::crypto::Ss58Codec;
    use sp_keyring::AccountKeyring;
    use std::{thread, time};

    /// Make sure env_logger is initialized only once and every test function calls this
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn default_api() -> SubstrateApi {
        SubstrateApi(Api::new("ws://127.0.0.1:9944".into()))
    }

    /// Create a dummy registered user
    fn new_registered_user() -> SubstrateApi {
        let alice = AccountKeyring::Alice;
        let mut alice_api = default_api();
        alice_api.set_signer(alice.pair());

        let (user, _, _) = sr25519::Pair::generate_with_phrase(None);
        trace!("randomly generated user {:?}", user.public());

        let amount = 1_000_000_000;
        let user_account_id: AccountId = user.public().as_array_ref().to_owned().into();
        trace!("user account id is {:?}", user_account_id.to_ss58check());
        alice_api.transfer_balance(user_account_id.clone(), amount);
        info!(
            "transfered {} to {}",
            amount,
            user_account_id.to_ss58check()
        );

        let mut user_api = default_api();
        user_api.set_signer(user);

        info!("start user registration");
        user_api.register_user(1 as u128, vec![1; 128]);

        user_api
    }

    /// Create a dummy registered worker
    fn new_registered_worker() -> SubstrateApi {
        let alice = AccountKeyring::Alice;
        let mut alice_api = default_api();
        alice_api.set_signer(alice.pair());

        let (worker, _, _) = sr25519::Pair::generate_with_phrase(None);
        trace!("randomly generated worker {:?}", worker.public());

        let amount = 1_000_000_000;
        let worker_account_id: AccountId = worker.public().as_array_ref().to_owned().into();
        trace!(
            "worker account id is {:?}",
            worker_account_id.to_ss58check()
        );
        alice_api.transfer_balance(worker_account_id.clone(), amount);
        info!(
            "transfered {} to {}",
            amount,
            worker_account_id.to_ss58check()
        );

        let mut worker_api = default_api();
        worker_api.set_signer(worker);

        info!("start worker registration");
        worker_api.register_worker(1 as u128, Default::default());

        worker_api
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn print_metadata() {
        let api = default_api();
        api.print_metadata();
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn get_nonce() {
        init();

        let mut api = default_api();
        let alice = AccountKeyring::Alice;
        api.set_signer(alice.pair().clone());

        let (random_keypair, _) = sr25519::Pair::generate();
        let account_id: AccountId = random_keypair.public().as_array_ref().to_owned().into();

        api.transfer_balance(account_id.clone(), 1000_000_000);
        info!("transfered 1 mil to {:?}", account_id);
        assert_eq!(0, api.get_nonce(&account_id));

        api.set_signer(random_keypair);

        for i in 1..5 {
            api.transfer_balance(alice.to_account_id(), 10);
            info!("transfered 1000 to {:?}", alice.to_account_id());
            assert_eq!(i, api.get_nonce(&account_id));
        }
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn transfer_balance() {
        init();

        let from = AccountKeyring::Alice.pair();
        let mut api = default_api();
        api.set_signer(from);
        info!("Alice's Account Nonce is {}\n", api.0.get_nonce().unwrap());

        // define the recipient
        let to = AccountKeyring::Bob.to_account_id();
        trace!("to account id {:?}", to.to_ss58check());
        let xt = api.0.balance_transfer(to.into(), 42);
        info!("composed Extrinsic:\n {:?}\n", xt);

        // send and watch extrinsic until finalized
        let tx_hash = api.0.send_extrinsic(xt.hex_encode()).unwrap();
        info!("transaction got finalized. Hash: {:?}", tx_hash);

        let (random_receiver, _, _) = sr25519::Pair::generate_with_phrase(None);
        trace!("random receiver public key {:?}", random_receiver.public());

        let random_receiver_account_id: AccountId =
            random_receiver.public().as_array_ref().to_owned().into();
        trace!(
            "random receiver address {:?}",
            random_receiver_account_id.to_ss58check()
        );
        let xt = api
            .0
            .balance_transfer(random_receiver_account_id.into(), 1234);
        trace!("composed extrinsinc\n{:?}\n", xt);
        let tx_hash = api.0.send_extrinsic(xt.hex_encode()).unwrap();
        trace!("transaction got finalized with hash {:?}", tx_hash);
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn add_user() {
        init();

        let alice = AccountKeyring::Alice;
        let mut alice_api = default_api();
        alice_api.set_signer(alice.pair());

        let (user, _, _) = sr25519::Pair::generate_with_phrase(None);
        trace!("randomly generated user {:?}", user.public());

        let amount = 1_000_000_000;
        let user_account_id: AccountId = user.public().as_array_ref().to_owned().into();
        trace!("user account id is {:?}", user_account_id.to_ss58check());
        alice_api.transfer_balance(user_account_id.clone(), amount);
        info!(
            "transfered {} to {}",
            amount,
            user_account_id.to_ss58check()
        );

        let mut user_api = default_api();
        user_api.set_signer(user);

        info!("start user registration");
        user_api.register_user(1 as u128, vec![1; 128]);

        let user = user_api.get_user(user_account_id.clone());
        info!("got user {:?}", user);
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn add_worker() {
        init();

        let alice = AccountKeyring::Alice;
        let mut alice_api = default_api();
        alice_api.set_signer(alice.pair());

        let (worker, _, _) = sr25519::Pair::generate_with_phrase(None);
        trace!("randomly generated worker {:?}", worker.public());

        let (enclave_account, _) = sr25519::Pair::generate();
        let enclave_account_id: AccountId =
            enclave_account.public().as_array_ref().to_owned().into();

        let worker_account_id: AccountId = worker.public().as_array_ref().to_owned().into();
        let amount = 1_000_000_000;
        trace!(
            "worker account id is {:?}",
            worker_account_id.to_ss58check()
        );
        alice_api.transfer_balance(worker_account_id.clone(), amount);
        info!(
            "transfered {} to {}",
            amount,
            worker_account_id.to_ss58check()
        );

        let mut worker_api = default_api();
        worker_api.set_signer(worker);

        let (worker_in, worker_out) = channel();

        let handle: thread::JoinHandle<_> = thread::spawn(move || {
            let listener_api = default_api();

            worker_in
                .send(listener_api.listen_for_worker_added())
                .unwrap();
        });
        info!("start worker registration");
        let enclave = Enclave::<AccountId> {
            account_id: enclave_account_id,
            public_key: vec![1, 2, 3],
            attestation: vec![1, 2, 3],
        };
        worker_api.register_worker(1 as u128, enclave);

        info!("wait for WorkedAdded event");
        let worker_id = worker_out.recv().expect("receving worker id");

        let worker = worker_api.get_worker(worker_id);
        info!("worker is {:?}", worker);

        handle.join().unwrap();
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn submit_task() {
        init();
        let (task_in, task_out) = channel();

        let user_api = new_registered_user();

        let handle: thread::JoinHandle<_> = thread::spawn(move || {
            let listener_api = default_api();

            task_in
                .send(listener_api.listen_for_task_submitted())
                .unwrap();
        });

        thread::sleep(time::Duration::from_secs(1));

        // submit task
        user_api.submit_task(0, Default::default());

        let task_id = task_out
            .recv_timeout(time::Duration::from_secs(30))
            .unwrap();
        info!("received task with id {:?}", task_id.clone());
        handle.join().unwrap();

        let task = user_api.get_task(task_id);
        info!("got task {:?}", task);
    }

    #[test]
    #[ignore] // Ignore since it's relying on a running substrate-node
    fn accept_task() {
        init();
        let (task_in, task_out) = channel();

        let user_api = new_registered_user();

        user_api.submit_task(0, Default::default());

        let handle: thread::JoinHandle<_> = thread::spawn(move || {
            let listener_api = default_api();

            task_in
                .send(listener_api.listen_for_task_submitted())
                .unwrap();
        });
        let task_id = task_out
            .recv_timeout(time::Duration::from_secs(30))
            .unwrap();
        info!("received task with id {:?}", task_id.clone());

        handle.join().unwrap();

        let worker_api = new_registered_worker();

        let handle: thread::JoinHandle<_> = thread::spawn(move || {
            let api = default_api();
            info!("waiting for the task {:?}", &task_id);
            api.wait_all_task_accepted(vec![task_id]);
            info!("got the task {:?}", &task_id);
        });

        let hash = worker_api.accept_task(task_id, vec![1, 2, 3]);
        info!("extrinsic confirmed {:?}", hash);
        handle.join().unwrap();
    }
}
