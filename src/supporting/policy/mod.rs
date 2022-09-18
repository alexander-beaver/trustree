pub mod powerpolicy;

use crate::supporting::trust::ScoredSecurityPolicy;
use std::fmt;

pub enum ScopeType {
    /// Evaluate scope on direct string comparison
    Equals,
    /// Evaluate scope on regex match
    Regex,
    /// Evaluate scope on all scopes
    All,
}
impl fmt::Display for ScopeType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ScopeType::Equals => write!(f, "Equals"),
            ScopeType::Regex => write!(f, "REGEX"),
            ScopeType::All => write!(f, "ALL"),
        }
    }
}

/// Evaluate the score of a security policy's scope type
impl ScoredSecurityPolicy for ScopeType {
    fn score(&self) -> u32 {
        match *self {
            ScopeType::Equals => 1000,
            ScopeType::Regex => 100,
            ScopeType::All => 1,
        }
    }
}
pub struct PolicyScope {
    pub name: String,
    pub scope_type: ScopeType,
    pub scope_members: Vec<String>,
}
