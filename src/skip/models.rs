use serde::Deserialize;

#[derive(Deserialize)]
pub struct Capabilities {
    pub entropy: bool,
    pub key: bool,
    pub algorithm: String,
    pub local_system_id: String,
    pub remote_system_id: Vec<String>,
}

#[derive(Deserialize)]
pub struct Key {
    pub key_id: String,
    pub key: String,
}