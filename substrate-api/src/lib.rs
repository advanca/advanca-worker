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
use std::iter::FromIterator;

use log::{error, trace};

use pallet_balances::AccountData;

use advanca_node_primitives::{
    self, Ciphertext, Duration, Enclave, Privacy, Task, TaskSpec, TaskStatus, User, Worker,
};
use advanca_node_primitives::{AccountId, Balance, Hash};
use sp_core::sr25519;

use substrate_subxt::{
    advanca::advanca_core::*, advanca::AdvancaRuntime, balances::TransferCallExt,
    system::AccountStoreExt, Client, ClientBuilder, EventSubscription, EventsDecoder, PairSigner,
};

//TODO: use TaskId<T> from advanca_core
pub type TaskId = Hash;

pub struct SubstrateApi {
    pub client: Client<AdvancaRuntime>,
    signer: Option<PairSigner<AdvancaRuntime, sr25519::Pair>>,
}

impl SubstrateApi {
    /// Create an API without signer
    pub fn new(ws_url: &str) -> SubstrateApi {
        let client = async_std::task::block_on(
            ClientBuilder::<AdvancaRuntime>::new()
                .set_url(ws_url)
                .build(),
        )
        .expect("spawn client");
        // let client = ClientBuilder::<AdvancaRuntime>::new().set_url(ws_url).build().await.expect("substrate client creation works");
        SubstrateApi {
            client,
            signer: None,
        }
    }

    /// Set signer
    pub fn set_signer(&mut self, signer: sr25519::Pair) {
        self.signer = Some(PairSigner::<_, _>::new(signer));
    }

    pub fn signer(&self) -> &PairSigner<AdvancaRuntime, sr25519::Pair> {
        self.signer.as_ref().unwrap()
    }

    pub fn signer_mut(&mut self) -> &mut PairSigner<AdvancaRuntime, sr25519::Pair> {
        self.signer.as_mut().unwrap()
    }

    /// Return genesis hash
    pub fn genesis_hash(&self) -> Hash {
        *self.client.genesis()
    }

    /// Helper function to get the runtime metadata
    pub fn print_metadata(&self) {
        let meta = self.client.metadata();

        println!("Metadata:\n {}", meta.pretty());
    }


    /// Get the nonce of the spcecified account
    pub fn get_nonce(&self, account: &AccountId) -> u32 {
        async_std::task::block_on(self.client.account(account, None))
            .expect("retrieve account nonce")
            .nonce
        // self.client.account(account, None).await.expect("retrieve account nonce").nonce
    }

    pub fn get_worker(&self, id: AccountId) -> Worker<AccountId> {
        async_std::task::block_on(self.client.workers(id, None)).expect("retrieve worker")
    }

    pub fn get_task(
        &self,
        id: TaskId,
    ) -> Task<TaskId, AccountId, Duration, TaskSpec<Privacy>, TaskStatus, Ciphertext> {
        async_std::task::block_on(self.client.tasks(id, None)).expect("retrieve task")
    }

    pub fn get_balance(&self, id: AccountId) -> AccountData<Balance> {
        async_std::task::block_on(self.client.account(&id, None))
            .expect("retrieve account balance")
            .data
    }

    pub fn get_user(&self, id: AccountId) -> User<AccountId> {
        async_std::task::block_on(self.client.users(id, None)).expect("retrieve user")
    }

    pub fn get_unscheduled_tasks(&self) -> Vec<TaskId> {
        async_std::task::block_on(self.client.unscheduled_tasks(None))
            .expect("retrieve unscheduled tasks")
    }

    pub fn transfer_balance(&self, to: AccountId, amount: Balance) -> Hash {
        async_std::task::block_on(self.client.transfer_and_watch(self.signer(), &to, amount))
            .expect("get transfer hash")
            .extrinsic
    }

    pub fn register_user(&self, deposit: Balance, public_key: Vec<u8>) -> Hash {
        async_std::task::block_on(self.client.register_user_and_watch(
            self.signer(),
            deposit,
            public_key,
        ))
        .expect("get register_user hash")
        .extrinsic
    }

    pub fn register_worker(&self, deposit: Balance, enclave: Enclave<AccountId>) -> Hash {
        async_std::task::block_on(self.client.register_worker_and_watch(
            self.signer(),
            deposit,
            enclave,
        ))
        .expect("get register_worker hash")
        .extrinsic
    }

    pub fn submit_task(
        &self,
        signed_user_task_pubkey: Vec<u8>,
        lease: Duration,
        task_spec: TaskSpec<Privacy>,
    ) -> Hash {
        async_std::task::block_on(self.client.submit_task_and_watch(
            self.signer(),
            signed_user_task_pubkey,
            lease,
            task_spec,
        ))
        .expect("get submit_task hash")
        .extrinsic
    }

    pub fn submit_task_evidence(&self, task_id: TaskId, evidence: Vec<Vec<u8>>) -> Hash {
        async_std::task::block_on(self.client.submit_task_evidence_and_watch(
            self.signer(),
            task_id,
            evidence,
        ))
        .expect("get submit_task_evidence hash")
        .extrinsic
    }

    pub fn accept_task(
        &self,
        task_id: TaskId,
        signed_eph_pubkey: Vec<u8>,
        url: Ciphertext,
    ) -> Hash {
        async_std::task::block_on(self.client.accept_task_and_watch(
            self.signer(),
            task_id,
            signed_eph_pubkey,
            url,
        ))
        .expect("get accept_task hash")
        .extrinsic
    }

    pub fn update_task(&self, task_id: TaskId, task_spec: TaskSpec<Privacy>) -> Hash {
        async_std::task::block_on(self.client.update_task_and_watch(
            self.signer(),
            task_id,
            task_spec,
        ))
        .expect("get update_task hash")
        .extrinsic
    }

    pub fn abort_task(&self, task_id: TaskId) -> Hash {
        async_std::task::block_on(self.client.abort_task_and_watch(self.signer(), task_id))
            .expect("get abort_task hash")
            .extrinsic
    }

    pub fn complete_task(&self, task_id: TaskId) -> Hash {
        async_std::task::block_on(self.client.complete_task_and_watch(self.signer(), task_id))
            .expect("get complete_task hash")
            .extrinsic
    }

    /// Listen for event WorkerAdded once
    ///
    /// Block the current thread and return the worker acount received
    pub fn listen_for_worker_added(&self) -> AccountId {
        let event =
            async_std::task::block_on(wait_for_event(&self.client, |_: &WorkerAddedEvent<_>| true))
                .expect("retrieve an event");
        event.worker
    }

    /// Listen for event TaskSubmitted once
    ///
    /// Block the current thread and return the task id received
    pub fn listen_for_task_submitted(&self) -> TaskId {
        let event =
            async_std::task::block_on(wait_for_event(&self.client, |_: &TaskSubmittedEvent<_>| {
                true
            }))
            .expect("retrieve an event");
        event.task_id
    }

    /// Wait until all the specified tasks are accepted
    ///
    /// Block the current thread
    pub fn wait_all_task_accepted(&self, task_ids: Vec<TaskId>) {
        self.wait_all_task_on_condition(task_ids, |e: &TaskAcceptedEvent<AdvancaRuntime>| {
            e.task_id
        });
    }

    /// Wait until all the specified tasks are aborted
    ///
    /// Block the current thread
    pub fn wait_all_task_aborted(&self, task_ids: Vec<TaskId>) {
        self.wait_all_task_on_condition(task_ids, |e: &TaskAcceptedEvent<AdvancaRuntime>| {
            e.task_id
        });
    }

    /// Internal helper function for all wait_all_task_* functions
    fn wait_all_task_on_condition<E, F>(&self, task_ids: Vec<TaskId>, task_id_accessor: F)
    where
        F: Fn(&E) -> TaskId,
        // R: AdvancaCore + substrate_subxt::Runtime,
        E: substrate_subxt::Event<AdvancaRuntime> + std::fmt::Debug,
    {
        let mut received: HashMap<TaskId, bool> =
            task_ids.iter().map(|i| (i.clone(), false)).collect();
        let expected_ids: HashSet<TaskId> = HashSet::from_iter(task_ids);
        let mut count = 0;

        async_std::task::block_on(wait_for_event(&self.client, |e: &E| {
            let task_id = task_id_accessor(e);
            if expected_ids.contains(&task_id) {
                if let Some(seen) = received.get_mut(&task_id) {
                    if !*seen {
                        trace!("hit one task with id {:?}", task_id);
                        *seen = true;
                        count += 1;
                        if count == expected_ids.len() {
                            trace!("all task received, returning");
                        }
                    } else {
                        error!(
                            "received event '{:?}' with same task id(={}) twice, something is wrong",
                            e,
                            task_id
                        );
                    }
                    return true;
                }
            }
            false
        })).expect("retrieve an event");
    }
}

pub async fn wait_for_event<E, P, R>(
    api: &Client<R>,
    mut predicate: P,
) -> Result<E, Box<dyn std::error::Error>>
where
    P: FnMut(&E) -> bool,
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
            return Ok(event);
        }
    }
    Err("Cannot find the matching event".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use log::info;
    use sp_core::crypto::Pair;
    use sp_core::crypto::Ss58Codec;
    use sp_keyring::AccountKeyring;
    use std::sync::mpsc::channel;
    use std::{thread, time};

    /// Make sure env_logger is initialized only once and every test function calls this
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn default_api() -> SubstrateApi {
        SubstrateApi::new("ws://127.0.0.1:9998".into())
    }

    /// Create a dummy registered user
    fn new_registered_user() -> SubstrateApi {
        let alice = AccountKeyring::Alice;
        let mut alice_api = default_api();
        alice_api.set_signer(alice.pair());

        let (user, _, _) = sr25519::Pair::generate_with_phrase(None);
        trace!("randomly generated user {:?}", user.public());

        let amount = 1_000_000_000_000;
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

        let amount = 1_000_000_000_000;
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
        user_api.submit_task(vec![], Default::default(), Default::default());

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

        user_api.submit_task(vec![], Default::default(), Default::default());

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

        let hash = worker_api.accept_task(task_id, Default::default(), vec![1, 2, 3]);
        info!("extrinsic confirmed {:?}", hash);
        handle.join().unwrap();
    }
}
