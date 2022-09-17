use crate::supporting::trust::trusted_startup::TrustedStartupConfig;

#[derive(Clone, Debug)]
pub enum KeyloaderState{
    Unloaded,
    Loaded,
    Error,
    Unknown
}

pub trait Keyloader{
    fn load(&mut self);
    fn unload(&mut self);
    fn get_public_key(&self) -> String;
    fn get_private_key(&self) -> String;
    fn get_state(&self) -> KeyloaderState;

}

#[derive(Clone, Debug)]
pub struct FSKeyloader{
    path: String,
    state: KeyloaderState,
    public_key: String,
    private_key: String,
}

impl Keyloader for FSKeyloader{
    fn load(&mut self){
        let conf = std::fs::read_to_string(self.path.clone()).expect("Unable to read config file");
        let conf: TrustedStartupConfig = serde_json::from_str(&conf).expect("Unable to parse config file");
        self.public_key = conf.trust_root_public_key.clone();
        self.private_key = conf.trust_root_private_key;
        self.state = KeyloaderState::Loaded;
    }
    fn unload(&mut self){
        self.state = KeyloaderState::Unloaded;
    }
    fn get_public_key(&self) -> String{
        return self.public_key.clone();
    }
    fn get_private_key(&self) -> String{
        return self.private_key.clone();
    }
    fn get_state(&self) -> KeyloaderState{
        return self.state.clone();
    }
}
