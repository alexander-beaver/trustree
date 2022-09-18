use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::trust::certmgr::{CertificateIssuanceResponse, CertificateIssuanceResponseType, CertificateManagerConn, IssuedCertificate, SignedCertificateRequest};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use chrono;
pub struct LocalCertMgr{

}
impl CertificateManagerConn for LocalCertMgr {
    fn request_certificate<H: Hivemind>(&self, request: SignedCertificateRequest, hivemind: H) -> CertificateIssuanceResponse {
        let ephemeral_name: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        if hivemind.request_issuance(request.clone()) {
            return CertificateIssuanceResponse {
                response_type: CertificateIssuanceResponseType::Ok,
                certificate: Some(IssuedCertificate {
                    id: ephemeral_name,
                    issued_by: vec![],
                    public_key: request.clone().associated_public_key,
                    timestamp_issued: chrono::Utc::now().timestamp() as u64,
                    timestamp_expires: request.clone().certificate_request.timestamp_expires,
                    data: "".to_string(),
                    signature: "".to_string()
                })
            };
        }

        return CertificateIssuanceResponse {
            response_type: CertificateIssuanceResponseType::Unknown,
            certificate: None
        };
    }
}
