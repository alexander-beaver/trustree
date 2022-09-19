extern crate core;

use std::collections::HashMap;
use tt_rs::client::generate_signed_certificate_request;
use tt_rs::crypto::ecdsa::{generate_keypair, get_pem_from_private_key, get_pem_from_public_key};
use tt_rs::stdimpl::local_hivemind::LocalHivemind;
use tt_rs::supporting::datastore::hivemind::{HiveKey, Hivemind};
use tt_rs::supporting::trust::certmgr::{CertificateManagerConn, PrivateCertificate};
use tt_rs::supporting::ux::default_prints::print_copyright;

fn main() {
    print_copyright();
    let (root_private_key, root_public_key) = generate_keypair();
    let root_private_pem = get_pem_from_private_key(root_private_key);
    let root_public_pem = get_pem_from_public_key(root_public_key);

    let mut hivemind = LocalHivemind {
        store: HashMap::new(),
    };
    LocalHivemind::init(&hivemind);

    let root_cert = tt_rs::supporting::trust::certmgr::generate_root_certificate(
        String::from("$"),
        root_private_pem,
        root_public_pem,
        vec![
            "PermA".to_string(),
            "PermB".to_string(),
            "PermC".to_string(),
            "PermD".to_string(),
        ],
        vec![
            "RoleA".to_string(),
            "RoleB".to_string(),
            "RoleC".to_string(),
            "RoleD".to_string(),
        ],
    );

    let certmgr = tt_rs::stdimpl::local_certmgr::LocalCertMgr {};
    hivemind.set(
        format!("{}", root_cert.certificate.id.clone()),
        serde_json::to_string(&root_cert.certificate).unwrap(),
    );

    let (crt_1_private, crt_1_public) = generate_keypair();
    let res = certmgr.request_certificate(
        generate_signed_certificate_request(
            root_cert.clone(),
            get_pem_from_public_key(crt_1_public.clone()),
            "".to_string(),
            vec![
                "PermA".to_string(),
                "PermB".to_string(),
                "PermC".to_string(),
            ],
            vec![],
            60 * 60,
        ),
        &mut hivemind,
    );

    println!("{:?}", res);

    let cert1 = res.certificate;
    if cert1.is_none() {
        println!("Certificate 1 is none");
        return;
    }
    let cert1 = cert1.unwrap();

    let cert1_private_cert = PrivateCertificate {
        private_key: get_pem_from_private_key(crt_1_private.clone()),
        certificate: cert1.clone(),
    };

    let (crt_2_private, crt_2_public) = generate_keypair();
    let res = certmgr.request_certificate(
        generate_signed_certificate_request(
            cert1_private_cert,
            get_pem_from_public_key(crt_2_public),
            "".to_string(),
            vec!["PermA".to_string(), "PermB".to_string()],
            vec![],
            60 * 60,
        ),
        &mut hivemind,
    );
    println!("{:?}", res);

    let cert2 = res.clone().certificate;

    if cert2.is_none() {
        println!("Certificate 2 is none");
        return;
    }
    let cert2 = cert2.unwrap();
    let cert2_private_cert = PrivateCertificate {
        private_key: get_pem_from_private_key(crt_2_private.clone()),
        certificate: cert2.clone(),
    };
    let (crt_3_private, crt_3_public) = generate_keypair();
    let res = certmgr.request_certificate(
        generate_signed_certificate_request(
            cert2_private_cert,
            get_pem_from_public_key(crt_3_public),
            "".to_string(),
            vec!["PermA".to_string()],
            vec![],
            60 * 60,
        ),
        &mut hivemind,
    );

    let cert3 = res.clone().certificate;
    if cert3.is_none() {
        println!("Certificate 3 is none");
        return;
    }
    let cert3 = cert3.unwrap();
    println!("Cert 3: {}", cert3.id);

    println!("{:?}", res);
}
