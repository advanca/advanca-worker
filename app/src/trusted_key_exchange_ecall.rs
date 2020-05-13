use sgx_types::*;
extern "C" {
    pub fn sgx_ra_proc_msg2_trusted (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, p_msg2: *const sgx_ra_msg2_t, p_qe_target: *const sgx_target_info_t, p_report: *mut sgx_report_t, nonce: *mut sgx_quote_nonce_t) -> sgx_status_t;
    pub fn sgx_ra_get_msg3_trusted (eid: sgx_enclave_id_t, retval: *mut sgx_status_t, context: sgx_ra_context_t, quote_size: uint32_t, qe_report: *mut sgx_report_t, p_msg3: *mut sgx_ra_msg3_t, msg3_size: uint32_t) -> sgx_status_t;
}
