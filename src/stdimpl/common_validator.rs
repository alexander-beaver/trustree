use std::borrow::BorrowMut;
use std::fmt::Error;
use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::policy::powerpolicy::{PolicyTemplate, PolicyValidator, PolicyValidatorResponse};
use crate::supporting::policy::powerpolicy::PolicyValidatorVote::{Abstain, Invalid, Valid};
use crate::supporting::trust::certmgr::{Certificate, SignedCertificateRequest};

pub struct TemplateValidator{

}
impl PolicyValidator for TemplateValidator {
    fn validate(&self, request: SignedCertificateRequest, hivemind: Box<dyn Hivemind>) -> PolicyValidatorResponse {
        let template = hivemind.get(request.certificate_request.template.clone());
        if template.is_none(){
            return PolicyValidatorResponse{
                vote: Abstain,
                confidence: 0,
            };
        }
        let template = template.unwrap();

        let parsed_template: PolicyTemplate = serde_json::from_str(&template.as_str()).unwrap();




        return PolicyValidatorResponse{
            vote: Valid,
            confidence: 1000,
        };
    }
}

pub struct ChainOfTrustValidator{

}
impl PolicyValidator for ChainOfTrustValidator {
    fn validate(&self, request: SignedCertificateRequest, hivemind: Box<dyn Hivemind>) -> PolicyValidatorResponse {
        let mut keys = request.clone().certificate_request.issued_by;
        keys.reverse();
        for entry in keys{
            let cert = hivemind.get(entry.clone());
            if cert.is_none(){
                return PolicyValidatorResponse{
                    vote: Invalid,
                    confidence: 1000,
                };
            }
            let cert = cert.unwrap();


            let parsed_cert: Certificate = serde_json::from_str(cert.as_str()).unwrap();



        }
        if request.clone().certificate_request.issued_by[0] == "$/CERT/root"{
            return PolicyValidatorResponse{
                vote: Valid,
                confidence: 1000,
            };
        }
        return PolicyValidatorResponse{
            vote: Invalid,
            confidence: 1000,
        };
    }
}