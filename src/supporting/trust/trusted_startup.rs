use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct TrustedStartupConfig {
    pub trust_server_url: String,
    pub enable_trusted_runtime: bool,
    pub trust_root_public_key: String,
    pub trust_root_private_key: String
}

impl TrustedStartupConfig{
    pub fn load(path: String) -> TrustedStartupConfig {
        let conf = std::fs::read_to_string(path).expect("Unable to read config file");
        let conf: TrustedStartupConfig = serde_json::from_str(&conf).expect("Unable to parse config file");
        return conf;
    }
    pub fn init(&self) {
        println!("Entering Trusted Startup");
        if self.enable_trusted_runtime {

        }else{
            println!("Trusted Runtime Bypassed.");
        }
    }
}


