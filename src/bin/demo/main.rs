extern crate core;


use openssl::base64;
use tt_rs::crypto::ecdsa::{generate_keypair, sign_data};
use tt_rs::supporting::ux::default_prints::print_copyright;
use tt_rs::stdimpl::local_hivemind::LocalHivemind;
use tt_rs::supporting::datastore::hivemind::Hivemind;

fn main() {
    print_copyright();
    let (root_private_key, root_public_key) = generate_keypair();

    let mut hivemind = LocalHivemind::init();
}
