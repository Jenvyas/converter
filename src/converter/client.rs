use std::net::SocketAddr;

use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::Status;
use tonic::metadata::Ascii;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;

use crate::converter::rpc::etsi_to_skip_converter_client::EtsiToSkipConverterClient;
use crate::converter::rpc::{NewKey, SaeId};

#[derive(Debug, Clone)]
pub struct EtsiToSkipClientHandle {
    tx: tokio::sync::mpsc::Sender<EtsiToSkipClientRequest>,
}

impl EtsiToSkipClientHandle {
    pub(crate) async fn new_keys(&self, keys: Vec<NewKey>) -> Result<(), tonic::Status> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(EtsiToSkipClientRequest::NewKeys(keys, tx)).await;
        rx.await.unwrap()
    }

    pub(crate) async fn get_connected_sae(&self) -> Result<(String, Vec<SaeId>), tonic::Status> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(EtsiToSkipClientRequest::GetConnectedSae(tx)).await;
        rx.await.unwrap()
    }
}

impl EtsiToSkipClientHandle {
    pub(crate) async fn new(addr: SocketAddr, provider_id: &str, tls: ClientConfig) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
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
        let provider: MetadataValue<_> = provider_id.parse()?;
        let channel = InterceptedService::new(inner, EtsiToSkipInterceptor { provider });

        let uri = Uri::builder().scheme("https").authority(addr.to_string()).build()?;
        let mut client = EtsiToSkipConverterClient::with_origin(channel, uri);

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        // Spawn a task for handling incoming converter requests.
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req {
                    EtsiToSkipClientRequest::NewKeys(items, sender) => {
                        let stream = tokio_stream::iter(items.into_iter());
                        let res = client.new_keys(tonic::Request::new(stream)).await;
                        let res = res.map(|response| response.into_inner());
                        let _ = sender.send(res);
                    }
                    EtsiToSkipClientRequest::GetConnectedSae(sender) => {
                        let result = client.get_connected_sae(tonic::Request::new(())).await;
                        match result {
                            Ok(res) => {
                                let id = res
                                    .metadata()
                                    .get("key_provider")
                                    .and_then(|val| val.to_str().ok())
                                    .map(|id| id.to_owned())
                                    .ok_or(Status::unauthenticated("No key_provider ID provided."));

                                match id {
                                    Ok(id) => {
                                        let stream = res.into_inner();
                                        // Collect the Sae Ids into a vector, stopping on the first Error, returning a Status.
                                        let sae_ids: Result<Vec<SaeId>, Status> = stream.collect().await;
                                        let response = sae_ids.map(|sae_ids| (id, sae_ids));
                                        let _ = sender.send(response);
                                    }
                                    Err(err) => {
                                        let _ = sender.send(Err(err));
                                    }
                                }
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
    NewKeys(Vec<NewKey>, oneshot::Sender<Result<(), tonic::Status>>),
    GetConnectedSae(oneshot::Sender<Result<(String, Vec<SaeId>), tonic::Status>>),
}
