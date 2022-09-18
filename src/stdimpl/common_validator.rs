use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::policy::powerpolicy::{PolicyTemplate, PolicyValidator, PolicyValidatorResponse};
use crate::supporting::policy::powerpolicy::PolicyValidatorVote::{Abstain, Invalid, Valid};
use crate::supporting::trust::certmgr::SignedCertificateRequest;

pub struct TemplateValidator{

}
impl PolicyValidator for TemplateValidator {
    fn validate<H: Hivemind>(&self, request: SignedCertificateRequest, hivemind: &H) -> PolicyValidatorResponse {
        let template = hivemind.get(request.template.clone());
        if template.is_none(){
            return PolicyValidatorResponse{
                vote: Abstain,
                confidence: 0,
            };
        }
        let template = template.unwrap();

        let parsed_template: Err<PolicyTemplate> = serde_json::from_str(&template.as_str());
        if parsed_template.is_err(){
            return PolicyValidatorResponse{
                vote: Invalid,
                confidence: 1000,
            };
        }
        let parsed_template = parsed_template.unwrap();
        


        return PolicyValidatorResponse{
            vote: Valid,
            confidence: 1000,
        };
    }
}

pub struct ChainOfTrustValidator{

}
impl PolicyValidator for ChainOfTrustValidator {
    fn validate<H: Hivemind>(&self, request: SignedCertificateRequest, hivemind: &H) -> PolicyValidatorResponse {
        return PolicyValidatorResponse{
            vote: Valid,
            confidence: 1000,
        };
    }
}