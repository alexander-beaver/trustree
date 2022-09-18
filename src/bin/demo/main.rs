extern crate core;


use openssl::base64;
use tt_rs::crypto::ecdsa::{generate_keypair, sign_data};
use tt_rs::supporting::ux::default_prints::print_copyright;
use tt_rs::stdimpl::local_hivemind::LocalHivemind;
use tt_rs::supporting::datastore::hivemind::{HiveKey, Hivemind};
use tt_rs::supporting::trust::certmgr::{CertificateManagerConn, CertificateRequest, SignedCertificateRequest};

fn main() {
    print_copyright();
    let (root_private_key, root_public_key) = generate_keypair();
    let root_private_pem = base64::encode_block(root_private_key.private_key_to_pem().unwrap().as_slice());
    let root_public_pem = base64::encode_block(root_public_key.public_key_to_pem().unwrap().as_slice());

    let mut hivemind = LocalHivemind::init();

    let root_cert = tt_rs::supporting::trust::certmgr::generate_root_certificate(String::from("$"),root_private_pem, root_public_pem);

    let certmgr = tt_rs::stdimpl::local_certmgr::LocalCertMgr{};
    hivemind.set(format!("{}",root_cert.id.clone()), serde_json::to_string(&root_cert).unwrap());

    let res = certmgr.request_certificate(SignedCertificateRequest{
        requested_by: "root".to_string(),
        certificate_request: CertificateRequest {
            issued_by: vec!["$/CERT/root".to_string()],
            issued_to: "stage1".to_string(),
            template: "".to_string(),
            scope: vec!["*".to_string()],
            timestamp_expires: 0,
        },
        signature: "".to_string(),
        associated_public_key: "".to_string()
    }, &mut hivemind);

    println!("{:?}", res);

    let cert1 = res.certificate.unwrap();
    hivemind.set(format!("{}",cert1.id.clone()), serde_json::to_string(&cert1).unwrap());
    let req2 = certmgr.request_certificate(SignedCertificateRequest{
        requested_by: cert1.issued_by.last().unwrap().clone(),
        certificate_request: CertificateRequest {
            issued_by: vec!["$/CERT/root".to_string(), cert1.id.clone()],
            issued_to: "stage2".to_string(),
            template: "".to_string(),
            scope: vec!["*".to_string()],
            timestamp_expires: 0,
        },
        signature: "".to_string(),
        associated_public_key: "".to_string()
    }, &mut hivemind);

    println!("{:?}", req2);
    println!("Root Certificate: {}", serde_json::to_string(&root_cert).unwrap());
}
