use std::fmt;

pub enum HiveKey {
    Cert,
    Perm
}

impl fmt::Display for HiveKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HiveKey::Cert => write!(f, "CERT"),
            HiveKey::Perm => write!(f, "PERM"),
        }
    }
}

/// Standard implementation for a Hivemind connection
pub trait Hivemind {
    /// Initialize the Hivemind connection
    fn init() -> Self;
    /// Check if a key exists in the Hivemind
    fn exists(&self, key: String) -> bool;
    /// Get a value from the Hivemind
    fn get(&self, key: String) -> Option<String>;
    /// Set a value in the Hivemind
    fn set(&mut self, key: String, value: String);
    /// Delete a value from the Hivemind
    fn delete(&mut self, key: String);
}