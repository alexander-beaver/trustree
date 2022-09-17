extern crate core;


use openssl::base64;
use tt_rs::crypto::ecdsa::{generate_keypair, sign_data};
use tt_rs::supporting::ux::default_prints::print_copyright;
use tt_rs::stdimpl::local_hivemind::LocalHivemind;
use tt_rs::supporting::datastore::hivemind::{HiveKey, Hivemind};

fn main() {
    print_copyright();
    let (root_private_key, root_public_key) = generate_keypair();
    let root_private_pem = root_private_key.private_key_to_pem().unwrap();
    let root_public_pem = root_public_key.public_key_to_pem().unwrap();

    let mut hivemind = LocalHivemind::init();

    let root_cert = tt_rs::supporting::trust::certmgr::generate_root_certificate(root_private_pem, root_public_pem);
}
