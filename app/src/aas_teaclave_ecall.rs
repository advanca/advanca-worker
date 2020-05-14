use sgx_types::*;
use advanca_crypto_ctypes::*;
extern "C" {
    pub fn enclave_init_ra (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, b_pse: i32, p_context: *mut sgx_ra_context_t) -> sgx_status_t;
    pub fn enclave_ra_close (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t) -> sgx_status_t;
    pub fn gen_worker_ec256_pubkey (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, worker_pubkey: &mut sgx_ec256_public_t) -> sgx_status_t;
    pub fn gen_worker_reg_request (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, aas_request: *mut CAasRegRequest) -> sgx_status_t;
    pub fn accept_task (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, task_id: &[u8;32], user_pubkey: &sgx_ec256_public_t) -> sgx_status_t;
    pub fn encrypt_msg (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, task_id: &[u8;32], msg_in: *const u8, msg_out: *mut u8, msg_len: u32) -> sgx_status_t;
}
