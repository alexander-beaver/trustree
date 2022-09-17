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
pub trait Hivemind {
    fn init() -> Self;
    fn exists(&self, key: String) -> bool;
    fn get(&self, key: String) -> Option<String>;
    fn set(&mut self, key: String, value: String);
    fn delete(&mut self, key: String);
}