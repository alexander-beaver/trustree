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
    fn exists(&self, key: &str) -> bool;
    fn get(&self, key: &str) -> Option<&str>;
    fn set(&mut self, key: &str, value: &str);
    fn delete(&mut self, key: &str);
}