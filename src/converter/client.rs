use std::fs::metadata;
use std::net::SocketAddr;

use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::Extensions;
use tonic::Status;
use tonic::metadata::Ascii;
use tonic::metadata::AsciiMetadataValue;
use tonic::metadata::MetadataMap;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tracing::info;

use crate::converter::rpc::etsi_to_skip_converter_client::EtsiToSkipConverterClient;
use crate::converter::rpc::{NewKey, SaeId};

#[derive(Debug, Clone)]
pub struct EtsiToSkipClientHandle {
    tx: tokio::sync::mpsc::Sender<EtsiToSkipClientRequest>,
}

impl EtsiToSkipClientHandle {
    pub(crate) async fn new_keys(&self, sae_pair: (String, String), keys: Vec<NewKey>) -> Result<(), tonic::Status> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(EtsiToSkipClientRequest::NewKeys(sae_pair, keys, tx)).await;
        rx.await.unwrap()
    }

    pub(crate) async fn get_connected_sae(&self) -> Result<(String, Vec<SaeId>), tonic::Status> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(EtsiToSkipClientRequest::GetConnectedSae(tx)).await;
        rx.await.unwrap()
    }
}

impl EtsiToSkipClientHandle {
    pub(crate) async fn new(
        addr: SocketAddr,
        remote_provider_id: String,
        local_provider_id: &str,
        tls: ClientConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        let connector = tower::ServiceBuilder::new()
            .layer_fn(move |s| {
                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls.clone())
                    .https_only()
                    .enable_http2()
                    .wrap_connector(s)
            })
            .service(http);

        let inner = Client::builder(TokioExecutor::new()).build(connector);

        // Add key provider id to the requests metadata.
        let local_provider: MetadataValue<_> = local_provider_id.parse()?;
        let channel = InterceptedService::new(
            inner,
            EtsiToSkipInterceptor {
                provider: local_provider.clone(),
            },
        );

        let uri = Uri::builder()
            .scheme("https")
            .authority(format!("localhost:{}", addr.port()))
            .path_and_query("/")
            .build()?;
        let mut client = EtsiToSkipConverterClient::with_origin(channel, uri);

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // Spawn a task for handling incoming converter requests.
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req {
                    EtsiToSkipClientRequest::NewKeys(sae_pair, items, sender) => {
                        info!("Sending {} new keys to peer '{}'", items.len(), remote_provider_id);
                        let stream = tokio_stream::iter(items.into_iter());
                        let mut req = tonic::Request::new(stream);
                        let master_ascii: MetadataValue<_> = sae_pair.0.parse().unwrap();
                        let slave_ascii: MetadataValue<_> = sae_pair.1.parse().unwrap();
                        req.metadata_mut().insert("master_sae_id", master_ascii);
                        req.metadata_mut().insert("slave_sae_id", slave_ascii);

                        let res = client.new_keys(req).await;
                        let res = res.map(|response| response.into_inner());
                        let _ = sender.send(res);
                    }
                    EtsiToSkipClientRequest::GetConnectedSae(sender) => {
                        let result = client.get_connected_sae(tonic::Request::new(())).await;
                        match result {
                            Ok(res) => {
                                let stream = res.into_inner();
                                // Collect the Sae Ids into a vector, stopping on the first Error, returning a Status.
                                let sae_ids: Result<Vec<SaeId>, Status> = stream.collect().await;
                                let response = sae_ids.map(|sae_ids| (remote_provider_id.clone(), sae_ids));
                                let _ = sender.send(response);
                            }
                            Err(err) => {
                                let _ = sender.send(Err(err));
                            }
                        };
                    }
                }
            }
        });

        Ok(Self { tx })
    }
}

struct EtsiToSkipInterceptor {
    provider: MetadataValue<Ascii>,
}

impl Interceptor for EtsiToSkipInterceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        request.metadata_mut().insert("key_provider", self.provider.clone());
        Ok(request)
    }
}

enum EtsiToSkipClientRequest {
    NewKeys((String, String), Vec<NewKey>, oneshot::Sender<Result<(), tonic::Status>>),
    GetConnectedSae(oneshot::Sender<Result<(String, Vec<SaeId>), tonic::Status>>),
}
