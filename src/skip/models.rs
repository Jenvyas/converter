use serde::Deserialize;

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Capabilities {
    pub entropy: bool,
    pub key: bool,
    pub algorithm: String,
    pub localSystemID: String,
    pub remoteSystemID: Vec<String>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Key {
    pub keyId: String,
    pub key: String,
}