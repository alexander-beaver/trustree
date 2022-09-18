use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::policy::powerpolicy::{PolicyValidator, PolicyValidatorResponse};
use crate::supporting::trust::certmgr::SignedCertificateRequest;

pub struct TemplateValidator{

}
impl PolicyValidator for TemplateValidator {
    fn validate<H: Hivemind>(&self, request: SignedCertificateRequest, hivemind: &H) -> PolicyValidatorResponse {
        return PolicyValidatorResponse{
            valid: true,
            confidence: 1000,
        };
    }
}

pub struct ChainOfTrustValidator{

}
impl PolicyValidator for ChainOfTrustValidator {
    fn validate<H: Hivemind>(&self, request: SignedCertificateRequest, hivemind: &H) -> PolicyValidatorResponse {
        return PolicyValidatorResponse{
            valid: true,
            confidence: 1000,
        };
    }
}