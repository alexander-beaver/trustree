pub trait Hivemind {
    fn init() -> Self;
    fn exists(&self, key: &str) -> bool;
    fn get(&self, key: &str) -> Option<&str>;
    fn set(&mut self, key: &str, value: &str);
    fn delete(&mut self, key: &str);
}