use std::{pin::Pin, sync::Arc};

use crate::converter::{context::EtsiToSkipContext, rpc::SaeId};

use super::rpc;
use super::rpc::etsi_to_skip_converter_server::EtsiToSkipConverter;
use rpc::NewKey;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

#[derive(Debug, Clone)]
pub(super) struct EtsiToSkipConverterService {
    pub(super) context: Arc<EtsiToSkipContext>,
}

#[tonic::async_trait]
impl EtsiToSkipConverter for EtsiToSkipConverterService {
    async fn new_keys(&self, request: Request<Streaming<NewKey>>) -> Result<Response<()>, Status> {
        let ProviderExtension { id } = request.extensions().get().unwrap();
        if !self.context.has_peer(id).await {
            return Err(Status::failed_precondition("Peer hasn't sent a get_connected_sae request."));
        }

        let (metadata, _, mut stream) = request.into_parts();

        let master_sae_id = metadata
            .get("master_sae_id")
            .map(|id| id.to_str().map(|id| id.to_owned()).ok())
            .flatten();
        let slave_sae_id = metadata
            .get("slave_sae_id")
            .map(|id| id.to_str().map(|id| id.to_owned()).ok())
            .flatten();

        let sae_pair = match (master_sae_id, slave_sae_id) {
            (Some(id0), Some(id1)) => (id0, id1),
            _ => return Err(Status::unauthenticated("No SAE ID pair provided.")),
        };

        let mut new_keys = Vec::new();

        while let Some(key) = stream.message().await? {
            new_keys.push(key.id);
        }

        self.context.new_keys(&sae_pair, new_keys).await;

        Ok(().into())
    }

    type GetConnectedSaeStream = Pin<Box<dyn Stream<Item = Result<SaeId, Status>> + Send>>;

    async fn get_connected_sae(&self, request: Request<()>) -> Result<Response<Self::GetConnectedSaeStream>, Status> {
        let ProviderExtension { id } = request.extensions().get().unwrap();
        match request.remote_addr() {
            Some(addr) => {
                let _ = self.context.add_peer(id, addr).await;
            }
            None => return Err(Status::failed_precondition("Converter only supports network sockets")),
        }

        let connected_sae = self.context.connected_sae().into_iter().map(|id| Ok(id));
        let stream = Box::pin(tokio_stream::iter(connected_sae));

        Ok(Response::new(stream))
    }
}

pub(super) fn key_provider_intercept(mut req: Request<()>) -> Result<Request<()>, Status> {
    let key_provider = match req.metadata().get("key_provider") {
        Some(id) => match id.to_str() {
            Ok(str) => str.to_owned(),
            Err(_) => return Err(Status::unauthenticated("Malformed key provider ID")),
        },
        None => return Err(Status::unauthenticated("No key provider ID")),
    };

    req.extensions_mut().insert(ProviderExtension { id: key_provider });

    Ok(req)
}

#[derive(Clone)]
struct ProviderExtension {
    id: String,
}
