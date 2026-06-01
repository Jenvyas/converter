use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};
use tokio_rustls::rustls::ClientConfig;
use tracing::{error, info};

use crate::converter::{
    client::EtsiToSkipClientHandle,
    rpc::{NewKey, SaeId},
};
use crate::{converter::client, etsi014::models::GetKeysWithId};

pub type SaePair = (String, String);

#[derive(Debug)]
pub struct EtsiToSkipContext {
    // Stores a map of Remote_SAE_ID->Key_provider pairs.
    peer_providers: RwLock<HashMap<String, String>>,
    // Stores a set of key id's that are mapped from an ordered (master_SAE_id, slave_SAE_id) SAE pair.
    stored_keys: RwLock<HashMap<(String, String), HashSet<String>>>,
    // Stores a map of key_provider->converter_peer_rpc_client pairs.
    peer_clients: Mutex<HashMap<String, client::EtsiToSkipClientHandle>>,
    tls: ClientConfig,
    connected_sae_ids: HashSet<String>,
    pub provider_id: String,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl EtsiToSkipContext {
    pub fn new(
        connected_sae_ids: HashSet<String>,
        provider_id: String,
        root_store: Arc<RootCertStore>,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, BoxError> {
        let tls = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, key)?;

        Ok(EtsiToSkipContext {
            peer_providers: Default::default(),
            stored_keys: Default::default(),
            peer_clients: Default::default(),
            connected_sae_ids,
            provider_id,
            tls,
        })
    }
}

impl EtsiToSkipContext {
    /// Get the stored key count for a master_sae, slave_sae pair
    pub async fn stored_key_count(&self, sae_pair: &(String, String)) -> usize {
        self.stored_keys.read().await.get(sae_pair).map_or(0, |keys| keys.len())
    }

    pub async fn remote_sae_provider(&self, remote_sae_id: &str) -> Option<String> {
        self.peer_providers.read().await.get(remote_sae_id).map(|id| id.to_owned())
    }

    /// Notify the converter peer of new keys.
    pub async fn send_keys(&self, sae_pair: &(String, String), keys: Vec<NewKey>) -> Option<()> {
        let lock = self.peer_providers.read().await;
        let peer_id = lock.get(&sae_pair.1)?;
        let client = self.peer_clients.lock().await.get(peer_id).unwrap().clone();
        let _ = client.new_keys(sae_pair.clone(), keys).await;
        Some(())
    }

    pub async fn new_keys(&self, sae_pair: &(String, String), key_ids: Vec<String>) {
        let mut stored_keys = self.stored_keys.write().await;
        let keys = stored_keys.entry(sae_pair.clone()).or_insert(HashSet::new());
        for key in key_ids {
            keys.insert(key);
        }
    }

    /// Check if a peer is already registered in the context
    pub async fn has_peer(&self, provider_id: &str) -> bool {
        self.peer_clients.lock().await.contains_key(provider_id)
    }

    pub async fn connect_to_peer(
        &self,
        addr: SocketAddr,
        peer_provider_id: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client_handle = EtsiToSkipClientHandle::new(addr, peer_provider_id, &self.provider_id, self.tls.clone()).await?;

        let (provider_id, connected_sae) = loop {
            let result = loop {
                match timeout(Duration::from_secs(5), client_handle.get_connected_sae()).await {
                    Err(_) => {
                        error!("Connected SAE request attempt to '{addr}' failed after 5 seconds. Trying again.");
                    }
                    Ok(result) => break result,
                }
            };

            let _ = match result {
                Err(e) => {
                    error!("Failed to request connected SAE from '{addr}': {e}");
                    info!("Attempting connected SAE request to '{addr}' again in 5 seconds.");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Ok(client) => break client,
            };
        };
        self.peer_clients.lock().await.insert(provider_id.to_string(), client_handle);

        // Map the new SAE IDs to the key provider id
        let mut write_lock = self.peer_providers.write().await;
        for sae_id in connected_sae {
            info!("Adding converter peer '{}' associated SAE '{}'", provider_id, sae_id.id);
            write_lock.insert(sae_id.id, provider_id.to_string());
        }
        Ok(())
    }

    /// Check if the requested key IDs are valid for the SAE pair
    pub async fn check_keys(&self, sae_pair: &(String, String), keys: &GetKeysWithId) -> Result<(), String> {
        let mut key_lock = self.stored_keys.write().await;
        let stored_keys = key_lock
            .get_mut(sae_pair)
            .ok_or(format!("No keys stored for SAE pair ({}, {})", &sae_pair.0, &sae_pair.1))?;

        for key in &keys.key_IDs {
            if !stored_keys.contains(&key.key_ID) {
                Err(format!("{} requested an invalid key id: {}", sae_pair.1, key.key_ID))?;
            }
        }

        Ok(())
    }

    pub async fn remove_key(&self, sae_pair: &(String, String), key: &str) -> bool {
        let mut lock = self.stored_keys.write().await;
        let keys = lock.get_mut(sae_pair);
        if let Some(keys) = keys {
            return keys.remove(key);
        }
        false
    }

    // Get the SAE ID of all the SAE that this converter serves.
    pub fn connected_sae(&self) -> Vec<SaeId> {
        self.connected_sae_ids.iter().map(|id| SaeId { id: id.to_owned() }).collect()
    }
}
