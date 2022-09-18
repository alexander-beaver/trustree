use std::collections::HashMap;
use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::trust::certmgr::SignedCertificateRequest;

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
    fn exists(&self, key: String) -> bool {
        return self.store.contains_key(key.as_str());
    }

    fn get(&self, key: String) -> Option<String>{
        if self.exists(key.clone()){
            return Some(self.store.get(key.as_str()).unwrap().to_string());
        }
        return None;

    }
    fn set(&mut self, key: String, value: String){
        self.store.insert(key.parse().unwrap(), value.parse().unwrap());
    }
    fn delete(&mut self, key: String){
        self.store.remove(key.as_str());
    }

    fn request_issuance(&self, req: SignedCertificateRequest) -> bool {
        return true;
    }

    fn get_hivemind_path(&self) -> String {
        return "$".to_string();
    }
}