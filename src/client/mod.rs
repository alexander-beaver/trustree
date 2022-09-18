use openssl::base64;
use crate::crypto::ecdsa::{convert_pem_to_private_key, sign_data};
use crate::supporting::trust::certmgr::{CertificateRequest, PrivateCertificate, SignedCertificateRequest};

pub fn generate_certificate_request(cert: PrivateCertificate, template: String, scope: Vec<String>,
                                    ttl: u64) -> SignedCertificateRequest {
   let mut issuer = cert.clone().certificate.issued_by;
    issuer.push(cert.clone().certificate.id);

    let cr = CertificateRequest {
        issued_by: issuer,
        issued_to: "".to_string(),
        template: template,
        scope : vec![],
        timestamp_expires: chrono::Utc::now().timestamp() as u64 + (ttl as u64)
    };

    let signature = sign_data(convert_pem_to_private_key(
        cert.clone().private_key), serde_json::to_string(&cr).unwrap().as_bytes().to_vec());
    SignedCertificateRequest{
       requested_by: cert.certificate.id,

       certificate_request: cr.clone(),
       signature: base64::encode_block(signature.to_der().unwrap().as_slice()),
       associated_public_key: cert.certificate.public_key
   }
}

//certificate_request:  CertificateRequest{
//        issued_by: vec![],
//        issued_to: "".to_string(),
//        template: "".to_string(),
//        scope: vec![],
//        timestamp_expires: chrono::Utc::now().timestamp() as u64 + (ttl as u64),
//    }