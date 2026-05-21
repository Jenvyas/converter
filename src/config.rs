use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Psk {
    pub id: Vec<u8>,
    pub key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SkipAuth {
    RootCertificate(PathBuf),
    Psk(Psk),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkipConfig {
    pub address: SocketAddr,
    pub auth: SkipAuth,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Etsi014Config {
    pub address: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub sae_ids: HashSet<String>,
    pub sae_root_certs: Vec<PathBuf>,
}

#[derive(Debug)]
pub struct LoadedEtsi014Config<'a> {
    pub address: SocketAddr,
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub key: PrivateKeyDer<'a>,
    pub sae_ids: HashSet<String>,
    pub sae_root_store: RootCertStore,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConverterConfig {
    pub address: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub root_certs: Vec<PathBuf>,
    pub peer_address: Option<SocketAddr>,
}

#[derive(Debug)]
pub struct LoadedConverterConfig<'a> {
    pub address: SocketAddr,
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub key: PrivateKeyDer<'a>,
    pub root_store: RootCertStore,
    pub peer_address: Option<SocketAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub skip_client: SkipConfig,
    pub etsi_server: Etsi014Config,
    pub converter: ConverterConfig,
}

impl Config {
    pub fn load<'a>(self) -> AResult<LoadedConfig<'a>> {
        let Self {
            skip_client,
            etsi_server,
            converter,
        } = self;

        let mut converter_roots = RootCertStore::empty();
        for pem_file in converter.root_certs {
            let root_certs = load_certs(&pem_file)?;
            for cert in root_certs {
                converter_roots.add(cert)?;
            }
        }

        let converter_client_chain = load_certs(&converter.cert)?;
        let converter_key = PrivateKeyDer::from_pem_file(&converter.key)
            .map_err(|err| format!("Error while loading '{}': '{}'", converter.key.display(), err))?;

        let etsi_cert_chain = load_certs(&etsi_server.cert)?;
        let etsi_server_key = PrivateKeyDer::from_pem_file(etsi_server.key)
            .map_err(|err| format!("Error while loading '{}': '{}'", converter.key.display(), err))?;

        let mut sae_roots = RootCertStore::empty();
        for pem_file in etsi_server.sae_root_certs {
            let root_certs = load_certs(&pem_file)?;
            for cert in root_certs {
                sae_roots.add(cert)?;
            }
        }

        Ok(LoadedConfig {
            skip_client,
            etsi_server: LoadedEtsi014Config {
                address: etsi_server.address,
                cert_chain: etsi_cert_chain,
                key: etsi_server_key,
                sae_ids: etsi_server.sae_ids,
                sae_root_store: sae_roots,
            },
            converter: LoadedConverterConfig {
                address: converter.address,
                cert_chain: converter_client_chain,
                key: converter_key,
                root_store: converter_roots,
                peer_address: converter.peer_address,
            },
        })
    }
}

type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Struct with loaded certificate files
pub struct LoadedConfig<'a> {
    /// We keep skip config unloaded, because openssl takes raw filepaths
    pub skip_client: SkipConfig,
    pub etsi_server: LoadedEtsi014Config<'a>,
    pub converter: LoadedConverterConfig<'a>,
}

fn load_certs(filename: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let vector: Result<Vec<CertificateDer<'static>>, rustls::pki_types::pem::Error> = CertificateDer::pem_file_iter(filename)
        .map_err(|err| format!("Error when opening certificate file '{}': '{}'", filename.display(), err))?
        .collect();
    vector.map_err(|err| format!("Error while parsing certificate file '{}': '{}'", filename.display(), err))
}
