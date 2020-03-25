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

//! Contains mirrored struct definition of advanca-core pallet events
//!
//! TODO: try to use the enums defined in advanca-core, i.e.:
//! ```rust
//! decl_event!(
//!     pub enum Event<T>
//!     where
//!         AccountId = <T as system::Trait>::AccountId,
//!         TaskId = TaskId<T>,
//!     {
//!         UserAdded(AccountId),
//!         UserRemoved(AccountId),
//!         TaskSubmitted(TaskId),
//!         TaskUpdated(TaskId),
//!         TaskAccepted(TaskId),
//!         TaskCompleted(TaskId),
//!         TaskAborted(TaskId),
//!         WorkerAdded(AccountId),
//!         WorkerRemoved(AccountId),
//!     }
//! );
//! ```
use crate::{AccountId, TaskId};
use codec::Decode;

#[derive(Decode, Debug)]
pub struct UserAdded {
    pub account_id: AccountId,
}

#[derive(Decode, Debug)]
pub struct UserRemoved {
    pub account_id: AccountId,
}

#[derive(Decode, Debug)]
pub struct WorkerAdded {
    pub account_id: AccountId,
}

#[derive(Decode, Debug)]
pub struct WorkerRemoved {
    pub account_id: AccountId,
}

#[derive(Decode, Debug)]
pub struct TaskSubmitted {
    pub task_id: TaskId,
}

#[derive(Decode, Debug)]
pub struct TaskUpdated {
    pub task_id: TaskId,
}

#[derive(Decode, Debug)]
pub struct TaskAccepted {
    pub task_id: TaskId,
}

#[derive(Decode, Debug)]
pub struct TaskCompleted {
    pub task_id: TaskId,
}

#[derive(Decode, Debug)]
pub struct TaskAborted {
    pub task_id: TaskId,
}

pub trait Event: Decode {
    fn task_id(&self) -> TaskId;
}

impl Event for TaskAccepted {
    fn task_id(&self) -> TaskId {
        self.task_id
    }
}
impl Event for TaskAborted {
    fn task_id(&self) -> TaskId {
        self.task_id
    }
}
