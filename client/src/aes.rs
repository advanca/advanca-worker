use advanca_crypto::secp256r1_public;
use advanca_crypto::sgx_enclave::sgx_enclave_utils as enclave_utils;
use advanca_crypto_types::*;
use sgx_types::*;

pub fn derive_session_key(
    worker_pubkey: &Secp256r1PublicKey,
    client_prvkey: &Secp256r1PrivateKey,
) -> [u8; 16] {
    let pubkey = secp256r1_public::to_sgx_ec256_public(&worker_pubkey);
    let prvkey = sgx_ec256_private_t { r: client_prvkey.r };

    let mut gab_x = sgx_ec256_dh_shared_t::default();
    let _ = enclave_utils::derive_ec256_shared_dhkey(&pubkey, &prvkey, &mut gab_x);
    let key0 = sgx_cmac_128bit_key_t::default();
    let p_src = &gab_x as *const sgx_ec256_dh_shared_t as *const u8;
    let src_len = core::mem::size_of::<sgx_ec256_dh_shared_t>() as u32;
    let mut mac = sgx_cmac_128bit_key_t::default();
    let _ = unsafe { sgx_rijndael128_cmac_msg(&key0, p_src, src_len, &mut mac) };
    mac
}

pub fn aes128_gcm_decrypt(key: [u8; 16], ivmaccipher: Vec<u8>) -> Vec<u8> {
    let mut plaintext = vec![0_u8; ivmaccipher.len() - 12 - 16];
    let ret = enclave_utils::aes128_gcm_decrypt(&key, &ivmaccipher, &[], &mut plaintext);
    println!("decrypt: {:?}", ret);
    plaintext
}

pub fn aes128_gcm_encrypt(key: [u8; 16], plaintext: Vec<u8>) -> Vec<u8> {
    let mut ivmaccipher = vec![0_u8; plaintext.len() + 12 + 16];
    let ret = enclave_utils::aes128_gcm_encrypt(&key, &plaintext, &[], &mut ivmaccipher);
    println!("encrypt: {:?}", ret);
    ivmaccipher
}
