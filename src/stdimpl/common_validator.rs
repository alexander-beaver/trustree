use std::borrow::BorrowMut;
use std::fmt::Error;

use openssl::base64;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;

use crate::crypto::ecdsa::verify_signature;
use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::policy::powerpolicy::{PolicyTemplate, PolicyValidator, PolicyValidatorResponse};
use crate::supporting::policy::powerpolicy::PolicyValidatorVote::{Abstain, Invalid, Valid};
use crate::supporting::trust::certmgr::{Certificate, SignedCertificateRequest};

pub struct TemplateValidator {}

impl PolicyValidator for TemplateValidator {
    fn validate(&self, request: SignedCertificateRequest, hivemind: Box<dyn Hivemind>)
        -> PolicyValidatorResponse {
        if request.certificate_request.template == ""{
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
    fn validate(&self, request: SignedCertificateRequest,
                hivemind: Box<dyn Hivemind>) -> PolicyValidatorResponse {
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
            if !verify_signature(EcKey::public_key_from_pem(base64::decode_block(
                parsed_cert.public_key.as_str()).unwrap().as_slice()).unwrap(),
                                 cert.as_bytes().to_vec(),
                                 EcdsaSig::from_der(
                                     base64::decode_block(
                                         request.signature.as_str()).unwrap().as_slice())
                                     .unwrap()) {
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