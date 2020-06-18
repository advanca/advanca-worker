use sgx_types::*;
extern "C" {
    pub fn enclave_init (eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn create_storage (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, public_key: *const u8, public_key_size: u32) -> sgx_status_t;
    pub fn storage_request (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, request: *const u8, request_size: u32, response: *mut u8, response_capacity: u32, response_size: *mut u32) -> sgx_status_t;
    pub fn get_sr25519_public_key (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, public_key: *mut u8, public_key_size: u32) -> sgx_status_t;
    pub fn enclave_init_ra (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, b_pse: i32, p_context: *mut sgx_ra_context_t) -> sgx_status_t;
    pub fn enclave_ra_close (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn proc_heartbeat (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, ubuf: *mut u8, ubuf_size: *mut usize, msg: *const u8, msg_len: usize) -> sgx_status_t;
    pub fn gen_worker_ec256_pubkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn get_worker_ec256_pubkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, ubuf: *mut u8, ubuf_size: *mut usize) -> sgx_status_t;
    pub fn get_task_ec256_pubkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, ubuf: *mut u8, ubuf_size: *mut usize, task_id: *const u8) -> sgx_status_t;
    pub fn gen_worker_reg_request (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, ubuf: *mut u8, ubuf_size: *mut usize, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn accept_task (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, task_id: *const u8, user_pubkey: *const u8, user_pubkey_size: usize) -> sgx_status_t;
    pub fn encrypt_msg (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, ubuf: *mut u8, ubuf_size: *mut usize, task_id: *const u8, msg_in: *const u8, msg_in_len: usize) -> sgx_status_t;
}