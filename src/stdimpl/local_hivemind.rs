use std::collections::HashMap;
use crate::supporting::datastore::hivemind::Hivemind;

pub struct LocalHivemind{
    store: HashMap<String, String>
}
impl LocalHivemind{

}

impl Hivemind for LocalHivemind{
    fn init() -> Self {
        return LocalHivemind{
            store: HashMap::new()
        };
    }
    fn exists(&self, key: &str) -> bool {
        return self.store.contains_key(key);
    }

    fn get(&self, key: &str) -> Option<&str>{
        if self.exists(key) {
            return Some(self.store.get(key).unwrap());
        }
        return None;

    }
    fn set(&mut self, key: &str, value: &str){
        self.store.insert(key.parse().unwrap(), value.parse().unwrap());
    }
    fn delete(&mut self, key: &str){
        self.store.remove(key);
    }
}