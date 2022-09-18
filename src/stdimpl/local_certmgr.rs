use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::trust::certmgr::{CertificateIssuanceResponse, CertificateIssuanceResponseType, CertificateManagerConn, IssuedCertificate, SignedCertificateRequest};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use chrono;
pub struct LocalCertMgr{

}
impl CertificateManagerConn for LocalCertMgr {
    fn request_certificate<H: Hivemind>(&self, request: SignedCertificateRequest, hivemind: &mut H) -> CertificateIssuanceResponse {
        let mut ephemeral_name: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let mut run = true;
        while run{
            if !hivemind.exists(ephemeral_name.clone()){
                run = false;
                break;
            }else{
                ephemeral_name = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(64)
                    .map(char::from)
                    .collect();
            }
        }

        ephemeral_name = format!("{}/CERT/{}", hivemind.get_hivemind_path(), ephemeral_name);
        if hivemind.request_issuance(request.clone()) {
            return CertificateIssuanceResponse {
                response_type: CertificateIssuanceResponseType::Ok,
                certificate: Some(IssuedCertificate {
                    id: ephemeral_name,
                    issued_by: request.clone().certificate_request.issued_by,
                    public_key: request.clone().associated_public_key,
                    timestamp_issued: chrono::Utc::now().timestamp() as u64,
                    timestamp_expires: request.clone().certificate_request.timestamp_expires,
                    data: serde_json::to_string(&request.clone().certificate_request).unwrap(),
                    signature: request.signature,
                })
            };
        }

        return CertificateIssuanceResponse {
            response_type: CertificateIssuanceResponseType::Unknown,
            certificate: None
        };
    }
}
