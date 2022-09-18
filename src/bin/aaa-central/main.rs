extern crate core;

use openssl::base64;
use tt_rs::crypto::ecdsa::{generate_keypair, sign_data};
use tt_rs::supporting::ux::default_prints::print_copyright;

fn main() {
    print_copyright();

    let (privkey, pubkey) = generate_keypair();
    let message = sign_data(privkey, "Hello, World".to_string().into_bytes());
    println!(
        "{}",
        base64::encode_block(message.to_der().unwrap().as_slice())
    )
}
