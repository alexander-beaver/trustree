use crate::supporting::datastore::hivemind::{HiveKey, Hivemind};
use openssl::ec::EcKey;
use openssl::pkey::Private;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificateRequest {
    /// The issuer of this certificate
    ///
    /// This is a list of HiveKeys that are used to form the trust
    /// The first key is the root key, and the last key is the issuer
    pub issued_by: Vec<String>,
    pub issued_to: String,
    pub template: String,
    pub scope: Vec<String>,
    pub timestamp_expires: u64,
}

impl CertificateRequest{
    pub fn from_certificate(certificate: Certificate) -> CertificateRequest{
        CertificateRequest{
            issued_by: certificate.issued_by,
            issued_to: certificate.issued_to,
            template: certificate.template,
            scope: certificate.scope,
            timestamp_expires: certificate.timestamp_expires,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedCertificateRequest {
    pub requested_by: String,
    pub certificate_request: CertificateRequest,
    pub signature: String,
    pub associated_public_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivateCertificate {
    pub private_key: String,
    pub certificate: Certificate,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// A certificate that has been issued by the hivemind and certificate manager
pub struct Certificate {
    /// The ID of the certificate
    pub id: String,
    /// The IDs of the certificate chain that issued this certificate
    pub issued_by: Vec<String>,
    /// The ID of the endpoint that this certificate is issued to
    pub issued_to: String,
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
    /// The template that was used to generate this certificate
    pub template: String,
    /// The scope of the certificate
    pub scope: Vec<String>,
}

impl Certificate {
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
    pub fn from_json(json: String) -> Certificate {
        serde_json::from_str(&json).unwrap()
    }
}

/// Generates a root certificate given a private key and a public key
pub fn generate_root_certificate(
    hivemind_origin: String,
    private_key_pem: String,
    public_key_pem: String,
) -> PrivateCertificate {
    let root_cert = Certificate {
        id: format!("{}/{}/root", hivemind_origin, HiveKey::Cert).to_string(),
        issued_by: vec![],
        public_key: public_key_pem,
        timestamp_issued: chrono::Utc::now().timestamp() as u64,
        timestamp_expires: 1893502800, // 2030-01-01
        data: "".to_string(),
        signature: "".to_string(),
        template: "root".to_string(),
        scope: vec![],
        issued_to: "*".to_string(),
    };

    return PrivateCertificate {
        private_key: private_key_pem,
        certificate: root_cert,
    };
}

/// The valid responses when a certificate issuance request is submitted to the Certificate Manager
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CertificateIssuanceResponseType {
    /// The certificate issuance failed for an unknown reason
    Unknown,
    /// The certificate issuance completed successfully
    Ok,
    /// The certificate issuance failed because the certificate request was invalid
    InvalidRequest,
    /// The certificate issuance failed because a chain of trust could not be validated
    InvalidChainOfTrust,
}

impl fmt::Display for CertificateIssuanceResponseType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CertificateIssuanceResponseType::Unknown => write!(f, "UNKNOWN"),
            CertificateIssuanceResponseType::Ok => write!(f, "OK"),
            CertificateIssuanceResponseType::InvalidRequest => write!(f, "INVALID_REQUEST"),
            CertificateIssuanceResponseType::InvalidChainOfTrust => {
                write!(f, "INVALID_CHAIN_OF_TRUST")
            }
        }
    }
}

/// A response to a certificate issuance request
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificateIssuanceResponse {
    pub response_type: CertificateIssuanceResponseType,
    pub certificate: Option<Certificate>,
}

/// A connection to a Certificate Manager
pub trait CertificateManagerConn {
    /// Request a certificate from the Certificate Manager
    fn request_certificate<H: Hivemind>(
        &self,
        request: SignedCertificateRequest,
        hivemind: &mut H,
    ) -> CertificateIssuanceResponse;
}
