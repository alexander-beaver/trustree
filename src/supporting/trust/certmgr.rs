use std::fmt;
use serde::{Serialize, Deserialize};
use crate::supporting::datastore::hivemind::{HiveKey, Hivemind};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificateRequest{
    pub issued_by: String,
    pub issued_to: String,
    pub template: String,
    pub scope: Vec<String>,
    pub timestamp_expires: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedCertificateRequest{
    pub requested_by: String,
    pub certificate_request: CertificateRequest,
    pub signature: String,
    pub associated_public_key: String,
}

impl SignedCertificateRequest{

    /// Validate a certificate request
    pub fn validate(&self) -> bool{
        if self.requested_by == self.certificate_request.issued_by{
            return true;
        }
        return false;
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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


/// Generates a root certificate given a private key and a public key
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

/// The valid responses when a certificate issuance request is submitted to the Certificate Manager
#[derive(Serialize, Deserialize, Debug)]
pub enum CertificateIssuanceResponseType{
    /// The certificate issuance failed for an unknown reason
    Unknown,
    /// The certificate issuance completed successfully
    Ok,
    /// The certificate issuance failed because the certificate request was invalid
    InvalidRequest,
    /// The certificate issuance failed because a chain of trust could not be validated
    InvalidChainOfTrust,
}

impl fmt::Display for CertificateIssuanceResponseType{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CertificateIssuanceResponseType::Unknown => write!(f, "UNKNOWN"),
            CertificateIssuanceResponseType::Ok => write!(f, "OK"),
            CertificateIssuanceResponseType::InvalidRequest => write!(f, "INVALID_REQUEST"),
            CertificateIssuanceResponseType::InvalidChainOfTrust => write!(f, "INVALID_CHAIN_OF_TRUST"),
        }
    }
}

/// A response to a certificate issuance request
#[derive(Serialize, Deserialize, Debug)]
pub struct CertificateIssuanceResponse{
    pub response_type: CertificateIssuanceResponseType,
    pub certificate: Option<IssuedCertificate>,
}

/// A connection to a Certificate Manager
pub trait CertificateManagerConn {
    /// Request a certificate from the Certificate Manager
    fn request_certificate<H:Hivemind>(&self, request: SignedCertificateRequest, hivemind: H) -> CertificateIssuanceResponse;

}
