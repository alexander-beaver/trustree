use crate::stdimpl::common_validator::{ChainOfTrustValidator, DerivedValidator, TemplateValidator};
use crate::supporting::datastore::hivemind::Hivemind;
use crate::supporting::policy::powerpolicy::{PolicyValidator, PolicyValidatorVote};
use crate::supporting::trust::certmgr::SignedCertificateRequest;
use std::collections::HashMap;

pub struct LocalHivemind {
    pub store: HashMap<String, String>,
}
impl LocalHivemind {}

impl Hivemind for LocalHivemind {
    fn init(&self) -> bool {
        return true;
    }
    fn exists(&self, key: String) -> bool {
        return self.store.contains_key(key.as_str());
    }

    fn get(&self, key: String) -> Option<String> {
        if self.exists(key.clone()) {
            return Some(self.store.get(key.as_str()).unwrap().to_string());
        }
        return None;
    }
    fn set(&mut self, key: String, value: String) {
        self.store
            .insert(key.parse().unwrap(), value.parse().unwrap());
    }
    fn delete(&mut self, key: String) {
        self.store.remove(key.as_str());
    }

    fn request_issuance(&self, req: SignedCertificateRequest) -> bool {
        let mut valid = true;
        for validator in self.get_validators() {
            let response = validator.validate(req.clone(), self);
            if response.vote.to_string() == PolicyValidatorVote::Invalid.to_string() {
                println!("Invalid certificate request");
                valid = false;
            } else {
                println!("Valid certificate request");
            }
        }
        return valid;
    }

    fn get_hivemind_path(&self) -> String {
        return "$".to_string();
    }
    fn get_validators(&self) -> Vec<&dyn PolicyValidator> {
        return vec![
            &TemplateValidator {},
            &ChainOfTrustValidator {},
            &DerivedValidator {}
        ];
    }
}
