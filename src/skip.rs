use std::{net::SocketAddrV4, path::PathBuf};

use http_body_util::{BodyExt, Empty};
use hyper::{
    Request, Uri,
    body::{Buf, Bytes},
    client::conn::http1::SendRequest,
};
use hyper_util::rt::TokioIo;
use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use serde::Deserialize;
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_openssl::SslStream;

pub enum SkipAuth {
    Psk(Vec<u8>, Vec<u8>),
    CaCrt(PathBuf),
}

pub struct SkipClient {
    ssl_ctx: SslContext,
    sender: SendRequest<Empty<Bytes>>,
    kp_addr: SocketAddrV4,
    conn_handle: JoinHandle<()>,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl SkipClient {
    pub async fn new(addr: SocketAddrV4, auth: SkipAuth) -> Result<SkipClient> {
        let mut ctx = SslContextBuilder::new(SslMethod::tls())?;
        match auth {
            SkipAuth::Psk(key_id, key) => ctx.set_psk_client_callback(move |_, _, psk_id, psk| {
                psk_id[..key_id.len()].copy_from_slice(&key_id);
                psk_id[key_id.len()] = 0;
                psk[..key.len()].copy_from_slice(&key);
                Ok(key.len())
            }),
            SkipAuth::CaCrt(path_buf) =>  {
                ctx.set_certificate_chain_file(path_buf)?;
                ctx.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            },
        }

        ctx.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        let ssl_ctx = ctx.build();

        let (conn_handle, sender) = Self::create_connection(&ssl_ctx, &addr).await?;

        Ok(SkipClient {
            ssl_ctx,
            sender,
            kp_addr: addr,
            conn_handle,
        })
    }

    async fn create_connection(
        ssl_ctx: &SslContext,
        addr: &SocketAddrV4,
    ) -> Result<(tokio::task::JoinHandle<()>, SendRequest<Empty<Bytes>>)> {
        let stream = TcpStream::connect(addr).await?;
        let stream = SslStream::new(Ssl::new(ssl_ctx)?, stream)?;

        let io = TokioIo::new(stream);
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        let conn_handle = tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection error: {:?}", err);
            }
        });

        Ok((conn_handle, sender))
    }

    async fn check_connection(&mut self) -> Result<()> {
        if !self.conn_handle.is_finished() {
            return Ok(());
        }

        let (conn_handle, sender) = Self::create_connection(&self.ssl_ctx, &self.kp_addr).await?;

        self.conn_handle = conn_handle;
        self.sender = sender;

        Ok(())
    }

    async fn fetch_json<T>(&mut self, url: Uri) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.check_connection().await?;

        let req = Request::builder()
            .uri(url)
            .header(hyper::header::HOST, self.kp_addr.to_string())
            .body(Empty::<Bytes>::new())?;

        let res = self.sender.send_request(req).await?;

        let body = res.collect().await?.aggregate();

        Ok(serde_json::from_reader(body.reader())?)
    }

    pub async fn fetch_key(&mut self, remote_system_id: &str, size: Option<u16>) -> Result<Key> {
        let mut p_and_q = format!("/key?remoteSystemId={remote_system_id}");

        if let Some(size) = size {
            p_and_q = format!("{}&size={size}", p_and_q);
        }

        let url = Uri::builder()
            .scheme("https")
            .path_and_query(p_and_q)
            .build()?;

        self.fetch_json(url).await
    }

    pub async fn fetch_peer_key(&mut self, remote_system_id: &str, key_id: &str) -> Result<Key> {
        let p_and_q = format!("/key/{key_id}?remoteSystemId={remote_system_id}");

        let url = Uri::builder()
            .scheme("https")
            .path_and_query(p_and_q)
            .build()?;

        self.fetch_json(url).await
    }

    pub async fn fetch_capabilities(&mut self) -> Result<Capabilities> {
        let url = Uri::builder()
            .scheme("https")
            .path_and_query("/capabilities")
            .build()?;

        let capabilities = self.fetch_json(url).await?;

        Ok(capabilities)
    }
}

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
