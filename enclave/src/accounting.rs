#[derive(Default, Copy, Clone)]
pub struct AccountingInfo {
    // storage_* not use in demo
    // in demo, storage_* is directly provided by the Storage module
    pub storage_size: usize,
    pub storage_in: usize,
    pub storage_out: usize,
    pub enclave_total_in: usize,
    pub enclave_total_out: usize,
    pub compute: usize,
}

impl AccountingInfo {
    pub fn record_enclave_in(&mut self, amt: usize) {
        self.enclave_total_in += amt;
    }

    pub fn record_enclave_out(&mut self, amt: usize) {
        self.enclave_total_out += amt;
    }

    pub fn record_compute(&mut self, amt: usize) {
        self.compute += amt;
    }

    pub fn update_storage_size(&mut self, amt: usize) {
        self.storage_size = amt;
    }

    pub fn record_storage_in(&mut self, amt: usize) {
        self.storage_in += amt;
    }

    pub fn record_storage_out(&mut self, amt: usize) {
        self.storage_out += amt;
    }

    pub fn get_storage_size(&self) -> usize {
        self.storage_size
    }

    pub fn get_storage_in(&self) -> usize {
        self.storage_in
    }

    pub fn get_storage_out(&self) -> usize {
        self.storage_out
    }

    pub fn get_enclave_in(&self) -> usize {
        self.enclave_total_in
    }

    pub fn get_enclave_out(&self) -> usize {
        self.enclave_total_out
    }

    pub fn get_compute(&self) -> usize {
        self.compute
    }
}
