pub mod certmgr;
pub mod anchor;


/// Have a way to numerically compare the security level of different policies
/// **Higher is more secure**
pub trait ScoredSecurityPolicy {
    fn score(&self) -> u32;
}