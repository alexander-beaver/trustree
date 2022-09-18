use openssl::base64;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::*;

use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};

fn get_key_group() -> EcGroup {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    group
}

/// Gets a public key from a private key
pub fn get_public_key(group: &EcGroup, x: &EcKey<Private>) -> Result<EcKey<Public>, ErrorStack> {
    EcKey::from_public_key(group, x.public_key())
}

/// Generates a new ECDSA keypair
pub fn generate_keypair() -> (EcKey<Private>, EcKey<Public>) {
    let group = get_key_group();
    let privkey = EcKey::generate(&group).unwrap();
    let pubkey = get_public_key(&group, &privkey).unwrap();
    return (privkey, pubkey);
}

/// Signs a message with a private key
pub fn sign_data(keypair: EcKey<Private>, data: Vec<u8>) -> EcdsaSig {
    let res = EcdsaSig::sign(&*data, &keypair).unwrap();
    return res;
}

/// Verifies a signature with a public key
pub fn verify_signature(keypair: EcKey<Public>, data: Vec<u8>, signature: EcdsaSig) -> bool {
    let res = signature.verify(&*data, &keypair).unwrap();
    return res;
}

pub fn get_pem_from_private_key(key: EcKey<Private>) -> String {
    return base64::encode_block(key.private_key_to_pem().unwrap().as_slice());
}
pub fn convert_pem_to_private_key(pem: String) -> EcKey<Private> {
    let key = EcKey::private_key_from_pem(&base64::decode_block(&pem).unwrap()).unwrap();
    return key;
}
pub fn get_pem_from_public_key(key: EcKey<Public>) -> String {
    return base64::encode_block(key.public_key_to_pem().unwrap().as_slice());
}
pub fn convert_pem_to_public_key(pem: String) -> EcKey<Public> {
    let key = EcKey::public_key_from_pem(&base64::decode_block(&pem).unwrap()).unwrap();
    return key;
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_sign_data() {
        let (privkey, pubkey) = super::generate_keypair();
        let data = "Hello World".as_bytes().to_vec();
        let sig = super::sign_data(privkey, data.clone());

        let verified = super::verify_signature(pubkey, data, sig);
        assert_eq!(verified, true);
    }
}
