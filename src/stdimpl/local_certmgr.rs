use crate::supporting::trust::certmgr::{CertificateIssuanceResponse, CertificateManagerConn, SignedCertificateRequest};

impl CertificateManagerConn for LocalCertMgr{
    fn request_certificate(&self, request: SignedCertificateRequest) -> CertificateIssuanceResponse {
        todo!()
    }
}