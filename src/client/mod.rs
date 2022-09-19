use crate::crypto::ecdsa::{convert_pem_to_private_key, ecdsa_to_string, sign_data};
use crate::supporting::trust::certmgr::{
    CertificateRequest, PrivateCertificate, SignedCertificateRequest,
};

/// Generate a request for a certificate given a previous certificate
///
/// **NOTE: This does not issue the certificate. It must be submitted to HiveMind for validation**
/// issuing_certificate: The certificate used to issue
/// template: The template to use for the certificate
/// scope: The scope of the certificate
/// ttl: The time to live of the certificate
/// returns: A signed certificate request
pub fn generate_signed_certificate_request(
    issuing_certificate: PrivateCertificate,
    public_key: String,
    template: String,
    permissions: Vec<String>,
    scope: Vec<String>,
    ttl: u64,
) -> SignedCertificateRequest {
    let mut issuer = issuing_certificate.clone().certificate.issued_by;
    issuer.push(issuing_certificate.clone().certificate.id);

    let cr = CertificateRequest {
        issued_by: issuer,
        issued_to: "".to_string(),
        template,
        permissions,
        scope,
        timestamp_expires: chrono::Utc::now().timestamp() as u64 + (ttl as u64),
    };

    let signature = sign_data(
        convert_pem_to_private_key(issuing_certificate.clone().private_key),
        serde_json::to_string(&cr).unwrap().as_bytes().to_vec(),
    );
    SignedCertificateRequest {
        requested_by: issuing_certificate.certificate.id,

        certificate_request: cr.clone(),
        signature: ecdsa_to_string(signature),
        associated_public_key: public_key,
    }
}
