use serde::{Serialize, Deserialize};
use crate::supporting::datastore::hivemind::HiveKey;


#[derive(Serialize, Deserialize, Debug)]
pub struct Certificate{
    /// The ID of the certificate
    pub id: String,
    /// The IDs of the certificate chain that issued this certificate
    pub issued_by: Vec<String>,
    /// The IDs of the certificates that this certificate issues
    pub issues: Vec<String>,
    /// The public key of the certificate
    pub public_key: String,
    /// The private key of the certificate
    pub private_key: String,

    /// The timestamp of when the certificate expires
    pub timestamp_expires: u64,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct IssuedCertificate{
    /// The ID of the certificate
    pub id: String,
    /// The IDs of the certificate chain that issued this certificate
    pub issued_by: Vec<String>,
    /// The public key of the certificate
    pub public_key: String,
    /// The timestamp of when the certificate was issued
    pub timestamp_issued: u64,
    /// The timestamp of when the certificate expires
    pub timestamp_expires: u64,
    /// The data that was signed by the certificate
    pub data: String,
    /// The signature of the data
    pub signature: String,
}

pub fn generate_root_certificate(private_key_pem: String, public_key_pem: String) -> Certificate{
    let root_cert = Certificate{
        id: format!("{}/root",HiveKey::Cert).to_string(),
        issued_by: vec![],
        issues: vec![],
        public_key: public_key_pem,
        private_key: private_key_pem,
        timestamp_expires: 1893502800, // 2030-01-01
    };
    return root_cert;

}