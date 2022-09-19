use crate::supporting::policy::powerpolicy::PolicyValidator;
use crate::supporting::trust::certmgr::SignedCertificateRequest;
use std::fmt;

pub enum HiveKey {
    Cert,
    Template,
    Policy,
    Node,
    Actor
}

impl fmt::Display for HiveKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HiveKey::Cert => write!(f, "CERT"),
            HiveKey::Template => write!(f, "TEMPLATE"),
            HiveKey::Policy => write!(f, "POLICY"),
            HiveKey::Node => write!(f, "NODE"),
            HiveKey::Actor => write!(f, "ACTOR"),
        }
    }
}

/// Standard implementation for a Hivemind connection
pub trait Hivemind {
    /// Initialize the Hivemind connection
    fn init(&self) -> bool;
    /// Check if a key exists in the Hivemind
    fn exists(&self, key: String) -> bool;
    /// Get a value from the Hivemind
    fn get(&self, key: String) -> Option<String>;
    /// Set a value in the Hivemind
    fn set(&mut self, key: String, value: String);
    /// Delete a value from the Hivemind
    fn delete(&mut self, key: String);

    fn request_issuance(&self, req: SignedCertificateRequest) -> bool;

    fn get_hivemind_path(&self) -> String;

    fn get_validators(&self) -> Vec<&dyn PolicyValidator>;
}
