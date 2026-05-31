use std::{net::SocketAddr, pin::Pin};

use http_body_util::{BodyExt, Empty};
use hyper::{
    Request, StatusCode, Uri,
    body::{Buf, Bytes},
    client::conn::http1::SendRequest,
};
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_openssl::SslStream;
use tracing::error;

use crate::config::SkipAuth;
use crate::{
    config::Psk,
    skip::models::{Capabilities, Key},
};

pub mod models;

pub struct SkipClient {
    ssl_ctx: SslConnector,
    sender: SendRequest<Empty<Bytes>>,
    kp_addr: SocketAddr,
    conn_handle: JoinHandle<()>,
}

type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl SkipClient {
    pub async fn new(addr: SocketAddr, auth: SkipAuth) -> AResult<SkipClient> {
        let mut ctx = SslConnector::builder(SslMethod::tls())?;
        match auth {
            SkipAuth::Psk(Psk { key, id }) => ctx.set_psk_client_callback(move |_, _, psk_id, psk| {
                psk_id[..id.len()].copy_from_slice(&id);
                psk_id[id.len()] = 0;
                psk[..key.len()].copy_from_slice(&key);
                Ok(key.len())
            }),
            SkipAuth::RootCertificate(path) => {
                ctx.set_ca_file(&path)
                    .map_err(|err| format!("Error while trying to open '{}': '{}'", path.display(), err))?;
                ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
        }

        ctx.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        let ssl_ctx = ctx.build();
        let ssl = ssl_ctx.configure()?.into_ssl("localhost")?;


        let (conn_handle, sender) = Self::create_connection(ssl, &addr).await.map_err(|err| {
            error!("Error while trying to connect to key provider at '{}': '{}'", addr, err);
            err
        })?;

        Ok(SkipClient {
            ssl_ctx,
            sender,
            kp_addr: addr,
            conn_handle,
        })
    }

    async fn create_connection(
        ssl: Ssl,
        addr: &SocketAddr,
    ) -> AResult<(tokio::task::JoinHandle<()>, SendRequest<Empty<Bytes>>)> {
        let stream = TcpStream::connect(addr).await?;
        let mut stream = SslStream::new(ssl, stream)?;
        Pin::new(&mut stream).connect().await?;

        let io = TokioIo::new(stream);
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        let conn_handle = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection error: {:?}", err);
            }
        });

        Ok((conn_handle, sender))
    }

    async fn check_connection(&mut self) -> Result<(), StatusCode> {
        if !self.conn_handle.is_finished() {
            return Ok(());
        }

        let ssl = self.ssl_ctx.configure().unwrap().into_ssl("localhost").unwrap();

        let (conn_handle, sender) = Self::create_connection(ssl, &self.kp_addr).await.map_err(|e| {
            error!("Error while reestablishing connection to '{}': '{}'", self.kp_addr, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        self.conn_handle = conn_handle;
        self.sender = sender;

        Ok(())
    }

    async fn fetch_json<T>(&mut self, url: Uri) -> Result<T, StatusCode>
    where
        T: serde::de::DeserializeOwned,
    {
        self.check_connection().await?;

        let req = Request::builder()
            .uri(url.clone())
            .header(hyper::header::HOST, self.kp_addr.to_string())
            .body(Empty::<Bytes>::new())
            .map_err(|e| {
                error!("Error while creating SKIP request to '{}': '{}'", url, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let res = self.sender.send_request(req).await.map_err(|e| {
            error!("Error while sending a SKIP request to '{}': '{}'", url, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let body = res
            .collect()
            .await
            .map_err(|e| {
                error!("Error while receiving response from '{}': '{}'", url, e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .aggregate();

        Ok(serde_json::from_reader(body.reader()).map_err(|e| {
            error!("Error while parsing SKIP response from '{}': '{}'", url, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?)
    }

    pub async fn fetch_key(&mut self, remote_system_id: &str, size: Option<usize>) -> Result<Key, StatusCode> {
        let mut p_and_q = format!("/key?remoteSystemId={remote_system_id}");

        if let Some(size) = size {
            p_and_q = format!("{}&size={size}", p_and_q);
        }

        let url = Uri::builder().scheme("https").authority(self.kp_addr.to_string()).path_and_query(p_and_q).build().map_err(|e| {
            error!("Invalid requested uri: '{}'", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        self.fetch_json(url).await
    }

    pub async fn fetch_peer_key(&mut self, remote_system_id: &str, key_id: &str) -> Result<Key, StatusCode> {
        let p_and_q = format!("/key/{key_id}?remoteSystemId={remote_system_id}");

        let url = Uri::builder().scheme("https").authority(self.kp_addr.to_string()).path_and_query(p_and_q).build().map_err(|e| {
            error!("Invalid requested uri: '{}'", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        self.fetch_json(url).await
    }

    pub async fn fetch_capabilities(&mut self) -> Result<Capabilities, StatusCode> {
        let url = Uri::builder()
            .scheme("https")
            .authority(self.kp_addr.to_string())
            .path_and_query("/capabilities")
            .build()
            .map_err(|e| {
                error!("Invalid requested uri: '{}'", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let capabilities = self.fetch_json(url).await?;

        Ok(capabilities)
    }
}
