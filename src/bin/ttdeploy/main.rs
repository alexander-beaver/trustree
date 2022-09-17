use tt_rs::crypto::ecdsa::generate_keypair;
use tt_rs::supporting::ux::default_prints::print_copyright;

fn main() {
    print_copyright();
    println!("Scoping Project");

    // Check if files deploy.ttpub and deploy.ttpriv exist
    // If they do, then we can skip the key generation step
    // If they don't, then we need to generate a keypair
    if !std::path::Path::new("deploy.ttpub").exists() {
        println!("Generating keypair");
        let (privkey, pubkey) = generate_keypair();
        println!("Saving keypair");
        save_keypair(privkey, pubkey);
    }


}