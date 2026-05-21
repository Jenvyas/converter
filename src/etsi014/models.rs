use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
pub struct KeyContainer {
    pub keys: Vec<Key>,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct Key {
    pub key_ID: String,
    pub key: String,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct Status {
    pub source_KME_ID: String,
    pub target_KME_ID: String,
    pub master_SAE_ID: String,
    pub slave_SAE_ID: String,
    pub key_size: usize,
    pub stored_key_count: usize,
    pub max_key_count: usize,
    pub max_key_per_request: usize,
    pub max_key_size: usize,
    pub min_key_size: usize,
    pub max_SAE_ID_count: usize,
}

#[derive(Deserialize)]
pub struct GetKey {
    pub number: Option<usize>,
    pub size: Option<usize>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct KeyRequest {
    number: Option<usize>,
    size: Option<usize>,
    additional_slave_SAE_IDs: Option<Vec<String>>,
    extension_mandatory: Option<Value>,
    extension_optional: Option<Value>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct GetKeyWithId {
    pub key_ID: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct GetKeysWithId {
    pub key_IDs: Vec<GetKeyWithId>,
}

pub struct EncKeyRequest {
    pub number: usize,
    pub size: Option<usize>,
}

impl From<GetKey> for EncKeyRequest {
    fn from(value: GetKey) -> Self {
        EncKeyRequest {
            number: value.number.unwrap_or(1),
            size: value.size,
        }
    }
}

impl From<KeyRequest> for EncKeyRequest {
    fn from(value: KeyRequest) -> Self {
        EncKeyRequest {
            number: value.number.unwrap_or(1),
            size: value.size,
        }
    }
}
