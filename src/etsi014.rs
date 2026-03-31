use std::path::PathBuf;

use http_body_util::Full;
use hyper::{Request, Response, body::{Bytes, Incoming}};
use openssl::ssl::{self, SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod, SslVerifyMode, SslVersion};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct Etsi014Server {
    
}

impl Etsi014Server {
    async fn new(ca_file: PathBuf, private_key_file: PathBuf, ) -> Result<Self> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        builder.set_ca_file(ca_file)?;
        builder.set_private_key_file(private_key_file, SslFiletype::PEM)?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

        Ok(Etsi014Server {  })
    }
}

async fn handle_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    Ok(Response::new(Full::new(Bytes::from("placeholder"))))
}

