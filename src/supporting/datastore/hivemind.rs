pub trait Hivemind {
    fn init(&self) -> bool;
    fn exists(&self, key: &str) -> bool;
    fn get(&self, key: &str) -> Option<String>;
    fn set(&mut self, key: &str, value: &str);
    fn delete(&mut self, key: &str);
}