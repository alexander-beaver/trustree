use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::trust::certmgr::SignedCertificateRequest;
use core::fmt;
use serde::{Deserialize, Serialize};

/// The ways that a validator can vote on a specific request
pub enum PolicyValidatorVote {
    /// The validator believes that the request is valid
    Valid,
    /// The validator believes that the request is invalid
    Invalid,
    /// The validator does not want to make a decision on the request
    Abstain,
    /// The validator is unable to make a decision on the request
    Unknown,
}

impl PolicyValidatorVote {
    /// Convert a PolicyValidatorVote to a boolean
    /// *true* if it is valid
    /// *false* if it is not valid
    pub fn to_bool(&self) -> bool {
        match self {
            PolicyValidatorVote::Valid => true,
            PolicyValidatorVote::Invalid => false,
            PolicyValidatorVote::Abstain => false,
            PolicyValidatorVote::Unknown => false,
        }
    }
}
impl fmt::Display for PolicyValidatorVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PolicyValidatorVote::Valid => write!(f, "VALID"),
            PolicyValidatorVote::Invalid => write!(f, "INVALID"),
            PolicyValidatorVote::Abstain => write!(f, "ABSTAIN"),
            PolicyValidatorVote::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

pub struct PolicyValidatorResponse {
    /// Whether the validators believes that the action is valid
    pub vote: PolicyValidatorVote,

    /// The magnitude of the confidence that the validator has in its decision
    pub confidence: u32,
}
pub trait PolicyValidator {
    fn validate(
        &self,
        request: SignedCertificateRequest,
        hivemind: &Hivemind,
    ) -> PolicyValidatorResponse;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PolicyTemplate {}

pub enum PolicyTemplateValidationMethod {
    /// It must match direct string equality
    Exact,
    /// It must match a regex
    Regex,
    /// It must match based on security degree
    /// Higher security degrees mean more secure/restricted
    ///
    /// **Note: Your string must be a valid u32.** Otherwise, the system will vote invalid.
    SecurityDegree,
}

pub struct PolicyTemplateValidationDomain {
    /// The key that the validator will look for in the template
    pub key: String,

    /// The value that the validator will look for in the template
    pub value: String,

    /// The method that the validator will use to validate the template
    pub validation_method: PolicyTemplateValidationMethod,
}
