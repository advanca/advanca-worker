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

use sgx_types::*;

extern "C" {
    pub fn init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    pub fn get_sr25519_public_key(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        public_key: *mut u8,
        public_key_size: u32,
    ) -> sgx_status_t;

    pub fn storage_request(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        request: *const u8,
        request_size: u32,
        response: *mut u8,
        response_capacity: u32,
        response_size: *mut u32,
    ) -> sgx_status_t;

    pub fn create_storage(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        public_key: *const u8,
        public_key_size: u32,
    ) -> sgx_status_t;
}
