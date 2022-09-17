use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::*;

use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Signer;


fn get_key_group() -> EcGroup {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    group
}

pub fn get_public_key(group: &EcGroup, x: &EcKey<Private>) -> Result<EcKey<Public>, ErrorStack> {
    EcKey::from_public_key(group, x.public_key())
}
pub fn generate_keypair() -> (EcKey<Private>, EcKey<Public>) {
    let group = get_key_group();
    let privkey = EcKey::generate(&group).unwrap();
    let pubkey = get_public_key(&group, &privkey).unwrap();
    return (privkey, pubkey);
}

pub fn sign_data(keypair: EcKey<Private>, data: Vec<u8>) -> EcdsaSig {
    let res = EcdsaSig::sign(&*data, &keypair).unwrap();
    return res;
}

pub fn verify_signature(keypair: EcKey<Public>, data: Vec<u8>, signature: EcdsaSig) -> bool {
    let res = signature.verify(&*data, &keypair).unwrap();
    return res;
}

#[cfg(test)]
mod tests{

    #[test]
    fn test_sign_data(){
        let (privkey, pubkey) = super::generate_keypair();
        let data = "Hello World".as_bytes().to_vec();
        let sig = super::sign_data(privkey, data.clone());

        let verified = super::verify_signature(pubkey, data, sig);
        assert_eq!(verified, true);


    }

}