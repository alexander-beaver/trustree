use crate::crypto::ecdsa::{convert_pem_to_public_key, ecdsa_from_string, verify_signature};
use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::policy::powerpolicy::PolicyValidatorVote::{Abstain, Invalid, Valid};
use crate::supporting::policy::powerpolicy::{
    PolicyTemplate, PolicyValidator, PolicyValidatorResponse,
};
use crate::supporting::trust::certmgr::{
    Certificate, CertificateRequest, SignedCertificateRequest,
};

pub struct DerivedValidator {}
impl PolicyValidator for DerivedValidator {
    fn validate(
        &self,
        request: SignedCertificateRequest,
        hivemind: &Hivemind,
    ) -> PolicyValidatorResponse {
        let mut keys = request.clone().certificate_request.issued_by;
        keys.reverse();
        let keys_length = keys.len();
        // Iterate through each key (back to front)
        for index in 0..keys_length {
            let entry = keys[index].clone();
            let cert = hivemind.get(entry.clone());

            // Reject if the certificate doesn't exist
            if cert.is_none() {
                return PolicyValidatorResponse {
                    vote: Invalid,
                    confidence: 1000,
                };
            }
            let cert = cert.unwrap();

            let parsed_cert: Certificate = serde_json::from_str(cert.as_str()).unwrap();
            if parsed_cert.id == "$/CERT/root" {
                // TODO Implement boottime protection
                return PolicyValidatorResponse {
                    vote: Valid,
                    confidence: 1000,
                };
            }
            let issuer = parsed_cert.issued_by.last().unwrap().clone();
            let issuer_cert = hivemind.get(issuer.clone());
            if issuer_cert.is_none() {
                return PolicyValidatorResponse {
                    vote: Invalid,
                    confidence: 1000,
                };
            }
            let issuer_cert = issuer_cert.unwrap();
            let issuer_cert = Certificate::from_json(issuer_cert);
            for permission in parsed_cert.permissions {
                let is_in_issuer = issuer_cert.permissions.contains(&permission);
                if !is_in_issuer {
                    return PolicyValidatorResponse {
                        vote: Invalid,
                        confidence: 1000,
                    };
                }
            }
        }
        if request.clone().certificate_request.issued_by[0] == "$/CERT/root" {
            println!("Valid permission chain");
            return PolicyValidatorResponse {
                vote: Valid,
                confidence: 1000,
            };
        }
        return PolicyValidatorResponse {
            vote: Invalid,
            confidence: 1000,
        };
    }
}
pub struct TemplateValidator {}

impl PolicyValidator for TemplateValidator {
    fn validate(
        &self,
        request: SignedCertificateRequest,
        hivemind: &Hivemind,
    ) -> PolicyValidatorResponse {
        if request.certificate_request.template == "" {
            return PolicyValidatorResponse {
                vote: Abstain,
                confidence: 0,
            };
        }
        let template = hivemind.get(request.certificate_request.template.clone());
        if template.is_none() {
            return PolicyValidatorResponse {
                vote: Abstain,
                confidence: 0,
            };
        }
        let template = template.unwrap();

        let parsed_template: PolicyTemplate = serde_json::from_str(&template.as_str()).unwrap();

        return PolicyValidatorResponse {
            vote: Valid,
            confidence: 1000,
        };
    }
}

pub struct ChainOfTrustValidator {}

impl PolicyValidator for ChainOfTrustValidator {
    /// Validate that the chain of trust is valid
    fn validate(
        &self,
        request: SignedCertificateRequest,
        hivemind: &Hivemind,
    ) -> PolicyValidatorResponse {
        let mut keys = request.clone().certificate_request.issued_by;
        keys.reverse();
        let keys_length = keys.len();
        // Iterate through each key (back to front)
        for index in 0..keys_length {
            let entry = keys[index].clone();
            let cert = hivemind.get(entry.clone());

            // Reject if the certificate doesn't exist
            if cert.is_none() {
                return PolicyValidatorResponse {
                    vote: Invalid,
                    confidence: 1000,
                };
            }
            let cert = cert.unwrap();

            let parsed_cert: Certificate = serde_json::from_str(cert.as_str()).unwrap();
            if parsed_cert.id == "$/CERT/root" {
                // TODO Implement boottime protection
                return PolicyValidatorResponse {
                    vote: Valid,
                    confidence: 1000,
                };
            }
            let issuer = parsed_cert.issued_by.last().unwrap().clone();
            let issuer_cert = hivemind.get(issuer.clone());
            if issuer_cert.is_none() {
                return PolicyValidatorResponse {
                    vote: Invalid,
                    confidence: 1000,
                };
            }
            let issuer_cert = issuer_cert.unwrap();
            let issuer_cert = Certificate::from_json(issuer_cert);
            if !verify_signature(
                convert_pem_to_public_key(issuer_cert.public_key.clone()),
                serde_json::to_string(&CertificateRequest::from_certificate(parsed_cert.clone()))
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
                ecdsa_from_string(parsed_cert.signature.clone()),
            ) {
                return PolicyValidatorResponse {
                    vote: Invalid,
                    confidence: 1000,
                };
            }
        }
        if request.clone().certificate_request.issued_by[0] == "$/CERT/root" {
            println!("Valid chain of trust");
            return PolicyValidatorResponse {
                vote: Valid,
                confidence: 1000,
            };
        }
        return PolicyValidatorResponse {
            vote: Invalid,
            confidence: 1000,
        };
    }
}
