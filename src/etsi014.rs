mod handlers;
pub mod models;

use std::{collections::HashSet, io, net::SocketAddr, sync::Arc};

use axum::{Router, extract::Request, routing::get};
use const_format::concatcp;
use hyper::{StatusCode, body::Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    version::TLS13,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tower::Service;
use tracing::warn;

use models::GetKeysWithId;
use x509_parser::{
    parse_x509_certificate,
    prelude::{GeneralName, ParsedExtension},
};

use crate::{config::LoadedEtsi014Config, etsi014::models::EncKeyRequest};

type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const API_VER: &str = "/api/v1";

pub struct Etsi014Server {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router<Etsi014State>,
    converter_handle: mpsc::Sender<E014ConverterRequest>,
    valid_sae: HashSet<String>,
}

pub struct E014ConverterRequest {
    pub sae_id: String,
    pub remote_sae_id: String,
    pub req: E014ConverterRequestInner,
}

impl E014ConverterRequest {
    pub fn new(req: E014ConverterRequestInner, sae_id: String, remote_sae_id: String) -> Self {
        Self {
            sae_id,
            remote_sae_id,
            req,
        }
    }
}

pub enum E014ConverterRequestInner {
    Status(oneshot::Sender<Result<models::Status, StatusCode>>),
    EncKey(oneshot::Sender<Result<models::KeyContainer, StatusCode>>, EncKeyRequest),
    DecKey(oneshot::Sender<Result<models::KeyContainer, StatusCode>>, GetKeysWithId),
}

impl E014ConverterRequestInner {
    pub fn send_error(self, status: StatusCode) {
        match self {
            E014ConverterRequestInner::Status(sender) => {
                let _ = sender.send(Err(status));
            }
            E014ConverterRequestInner::EncKey(sender, _) => {
                let _ = sender.send(Err(status));
            }
            E014ConverterRequestInner::DecKey(sender, _) => {
                let _ = sender.send(Err(status));
            }
        };
    }
}

#[derive(Clone)]
pub struct Etsi014State {
    converter_handle: mpsc::Sender<E014ConverterRequest>,
    sae_id: String,
}

impl Etsi014Server {
    // Create a server and begin listening on the specificed socket address
    pub async fn new(config: LoadedEtsi014Config<'static>, converter_handle: mpsc::Sender<E014ConverterRequest>) -> AResult<Self> {
        let LoadedEtsi014Config {
            address,
            cert_chain,
            key,
            sae_ids,
            sae_root_store,
        } = config;

        let tls_config = rustls_server_config(Arc::new(sae_root_store), cert_chain, key)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind(address).await?;

        let app = Router::new()
            .route(concatcp!(API_VER, "/keys/{slave_SAE_ID}/status"), get(handlers::get_status))
            .route(
                concatcp!(API_VER, "/keys/{slave_SAE_ID}/enc_keys"),
                get(handlers::get_key).post(handlers::post_key),
            )
            .route(
                concatcp!(API_VER, "/keys/{master_SAE_ID}/dec_keys"),
                get(handlers::get_key_with_id).post(handlers::post_key_with_id),
            );

        Ok(Etsi014Server {
            acceptor,
            app,
            listener,
            converter_handle,
            valid_sae: sae_ids,
        })
    }

    /// Accept an mTLS connection and return a future that serves an ETSI QKD 014 API to the connection.
    pub async fn accept(&self) -> AResult<impl Future<Output = ()> + use<>> {
        let (tcp_stream, addr) = self.listener.accept().await?;
        let stream = self.acceptor.accept(tcp_stream).await?;

        // Check if the SAE ID is valid
        let (_, conn) = stream.get_ref();
        let cert = &conn
            .peer_certificates()
            .expect("The connection was accepted with client authentication enabled.")[0];
        let sae_id = extract_sae_id(&cert);
        let sae_id = match sae_id {
            Some(sae_id) if !self.valid_sae.contains(&sae_id) => {
                Err(Box::new(io::Error::new(io::ErrorKind::PermissionDenied, "Invalid SAE ID")))
            }
            None => Err(Box::new(io::Error::new(io::ErrorKind::PermissionDenied, "Invalid SAE ID"))),
            Some(sae_id) => Ok(sae_id),
        }?;

        let app = self.app.clone().with_state(Etsi014State {
            converter_handle: self.converter_handle.clone(),
            sae_id,
        });

        Ok(serve_connection(app, stream, addr))
    }
}

fn extract_sae_id(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = parse_x509_certificate(cert.as_ref()).ok()?;
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => return Some(dns.to_string()),
                    GeneralName::RFC822Name(email) => return Some(email.to_string()),
                    GeneralName::URI(uri) => return Some(uri.to_string()),
                    GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                        return Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string());
                    }
                    GeneralName::IPAddress(raw) if raw.len() == 16 => {
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(raw);
                        return Some(std::net::Ipv6Addr::from(bytes).to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

fn rustls_server_config(
    sae_auth_roots: Arc<RootCertStore>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    Ok(
        ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&TLS13])?
            .with_client_cert_verifier(WebPkiClientVerifier::builder(sae_auth_roots).build()?)
            .with_single_cert(cert_chain, key)?,
    )
}

async fn serve_connection(router: Router, tls_stream: TlsStream<TcpStream>, addr: SocketAddr) {
    let stream = TokioIo::new(tls_stream);

    let service = hyper::service::service_fn(move |request: Request<Incoming>| router.clone().call(request));

    let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(stream, service)
        .await;

    if let Err(err) = ret {
        warn!("error serving connection from {}: {}", addr, err);
    }
}
