extern crate core;


use std::collections::HashMap;
use openssl::base64;
use tt_rs::client::generate_signed_certificate_request;
use tt_rs::crypto::ecdsa::{generate_keypair, get_pem_from_private_key, get_pem_from_public_key, sign_data};
use tt_rs::supporting::ux::default_prints::print_copyright;
use tt_rs::stdimpl::local_hivemind::LocalHivemind;
use tt_rs::supporting::datastore::hivemind::{HiveKey, Hivemind};
use tt_rs::supporting::trust::certmgr::{CertificateManagerConn, CertificateRequest, issued_certificate_to_certificate, PrivateCertificate, SignedCertificateRequest};

fn main() {
    print_copyright();
    let (root_private_key, root_public_key) = generate_keypair();
    let root_private_pem = get_pem_from_private_key(root_private_key);
    let root_public_pem = get_pem_from_public_key(root_public_key);

    let mut hivemind = LocalHivemind{store: HashMap::new()};
    LocalHivemind::init(&hivemind);

    let root_cert = tt_rs::supporting::trust::certmgr::generate_root_certificate(String::from("$"),root_private_pem, root_public_pem);

    let certmgr = tt_rs::stdimpl::local_certmgr::LocalCertMgr{};
    hivemind.set(format!("{}",root_cert.certificate.id.clone()), serde_json::to_string(&root_cert.certificate).unwrap());

    let (crt_1_private, crt_1_public) = generate_keypair();
    let res = certmgr.request_certificate(
    generate_signed_certificate_request(root_cert.clone(), get_pem_from_public_key(crt_1_public),"".to_string(), vec![], 60*60), &mut hivemind);

    println!("{:?}", res);

    let cert1 = res.certificate.unwrap();

    let cert1_private_cert = PrivateCertificate{
        private_key: get_pem_from_private_key(crt_1_private),
        certificate: issued_certificate_to_certificate(cert1.clone())
    };

    let (crt_2_private, crt_2_public) = generate_keypair();
    let res = certmgr.request_certificate(
    generate_signed_certificate_request(cert1_private_cert, get_pem_from_public_key(crt_2_public),"".to_string(), vec![], 60*60), &mut hivemind);


}
