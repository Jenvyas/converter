use axum::http;
use hyper::StatusCode;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use rustls::{ServerConfig, server::WebPkiClientVerifier, version::TLS13};
use std::{collections::HashSet, sync::Arc};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;
use tonic::{body::Body, service::Routes};
use tower::ServiceExt;
use tracing::error;

pub mod rpc {
    tonic::include_proto!("converter");
}

use crate::{
    config::LoadedConverterConfig,
    converter::{
        context::EtsiToSkipContext,
        rpc::NewKey,
        server::{EtsiToSkipConverterService, key_provider_intercept},
    },
    etsi014::{
        E014ConverterRequest,
        models::{Key, KeyContainer, Status},
    },
    skip::SkipClient,
};
type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) mod client;
pub mod context;
pub mod server;

/// Etsi014 to Skip request converter handler.
///
/// Continues to receive requests while at least one request sender is still alive.
pub async fn etsi_to_skip_converter(
    mut etsi_receiver: mpsc::Receiver<E014ConverterRequest>,
    mut skip_client: SkipClient,
    sae_ids: HashSet<String>,
    config: LoadedConverterConfig<'static>,
) -> Result<(), BoxError> {
    let LoadedConverterConfig {
        address,
        cert_chain,
        key,
        peer_address,
        root_store,
    } = config;

    let capabilities = skip_client
        .fetch_capabilities()
        .await
        .map_err(|e| format!("Couldn't fetch initial capabilities from the key provider: {}", e))?;
    let root_store = Arc::new(root_store);
    let ctx = EtsiToSkipContext::new(
        sae_ids,
        capabilities.localSystemID,
        root_store.clone(),
        cert_chain.clone(),
        key.clone_key(),
    )?;

    let ctx = Arc::new(ctx);

    let mut tls = ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(WebPkiClientVerifier::builder(root_store).build()?)
        .with_single_cert(cert_chain, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];

    let server = EtsiToSkipConverterService { context: ctx.clone() };
    let service = Routes::new(rpc::etsi_to_skip_converter_server::EtsiToSkipConverterServer::with_interceptor(
        server,
        key_provider_intercept,
    ))
    .prepare();
    let http = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    let listener = TcpListener::bind(address).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    // Start a gRPC converter server
    tokio::spawn(async move {
        loop {
            let http = http.clone();
            let acceptor = acceptor.clone();
            let service = service.clone();
            let (conn, addr) = match listener.accept().await {
                Ok(incoming) => incoming,
                Err(e) => {
                    error!("Error accepting connection: {e}");
                    continue;
                }
            };

            tokio::spawn(async move {
                let acceptor = acceptor.clone();
                let conn = match acceptor.accept(conn).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!("Error while accepting TLS connection from '{addr}': {e}");
                        return;
                    }
                };

                let service = tower::ServiceBuilder::new().service(service);

                if let Err(e) = http
                    .serve_connection(
                        TokioIo::new(conn),
                        TowerToHyperService::new(service.map_request(|req: http::Request<_>| req.map(Body::new))),
                    )
                    .await
                {
                    error!("Error while serving connection '{addr}': {e}");
                    return;
                }
            });
        }
    });

    // Connect to a peer converter if an address is provided
    if let Some(addr) = peer_address {
        if let Err(e) = ctx.connect_to_peer(addr).await {
            error!("Failed to connect to converter peer '{}': '{}'", addr, e);
            return Err(e);
        }
    }

    loop {
        tokio::select! {
            request = etsi_receiver.recv() => {
                match request {
                    Some(request) => handle_etsi_request(ctx.clone(), &mut skip_client, request).await?,
                    None => break,
                };
            }
        }
    }

    Ok(())
}

/// Convert an Etsi014 request to a SKIP request and add additional context information to the converter context.
async fn handle_etsi_request(
    ctx: Arc<EtsiToSkipContext>,
    skip_client: &mut SkipClient,
    request: E014ConverterRequest,
) -> Result<(), BoxError> {
    let E014ConverterRequest {
        sae_id,
        remote_sae_id,
        req,
    } = request;

    let peer_key_provider = match ctx.remote_sae_provider(&remote_sae_id).await {
        Some(peer_key_provider) => peer_key_provider.to_owned(),
        None => {
            req.send_error(StatusCode::NOT_FOUND);
            return Err("Invalid Peer Id".into());
        }
    };

    let sae_pair = (sae_id, remote_sae_id);

    match req {
        crate::etsi014::E014ConverterRequestInner::Status(sender) => {
            let capabilities = match skip_client.fetch_capabilities().await {
                Ok(capabilities) => capabilities,
                Err(err) => {
                    let _ = sender.send(Err(err));
                    return Ok(());
                }
            };

            let stored_key_count = ctx.stored_key_count(&sae_pair).await;
            let (sae_id, remote_sae_id) = sae_pair;

            // Default status response, TODO: extract status info from the Skip KP.
            let _ = sender.send(Ok(Status {
                source_KME_ID: capabilities.localSystemID,
                target_KME_ID: peer_key_provider,
                master_SAE_ID: sae_id,
                slave_SAE_ID: remote_sae_id,
                key_size: 256,
                stored_key_count: stored_key_count,
                max_key_count: 8,
                max_key_per_request: 8,
                max_key_size: 1024,
                min_key_size: 256,
                max_SAE_ID_count: 0,
            }));
        }
        crate::etsi014::E014ConverterRequestInner::EncKey(sender, enc_key_request) => {
            let mut keys = Vec::with_capacity(enc_key_request.number);

            for _ in 0..enc_key_request.number {
                let key = skip_client.fetch_key(&peer_key_provider, enc_key_request.size).await;
                match key {
                    Ok(key) => {
                        keys.push(Key {
                            key_ID: key.keyId,
                            key: key.key,
                        });
                    }
                    Err(err) => {
                        let _ = sender.send(Err(err));
                        return Ok(());
                    }
                }
            }

            let new_keys = keys.iter().map(|key| NewKey { id: key.key_ID.clone() }).collect();
            ctx.send_keys(&sae_pair, new_keys).await;

            let _ = sender.send(Ok(KeyContainer { keys }));
        }
        crate::etsi014::E014ConverterRequestInner::DecKey(sender, get_keys_with_id) => {
            let sae_pair = (sae_pair.1, sae_pair.0);
            if let Err(err) = ctx.check_keys(&sae_pair, &get_keys_with_id).await {
                error!(err);
                let _ = sender.send(Err(StatusCode::UNAUTHORIZED));
                return Ok(());
            }
            let mut keys = Vec::with_capacity(get_keys_with_id.key_IDs.len());

            for key in get_keys_with_id.key_IDs {
                let res = skip_client.fetch_peer_key(&peer_key_provider, &key.key_ID).await;
                match res {
                    Ok(key) => {
                        ctx.remove_key(&sae_pair, &key.keyId).await;
                        keys.push(Key {
                            key_ID: key.keyId,
                            key: key.key,
                        });
                    }
                    Err(status) => {
                        let _ = sender.send(Err(status));
                        return Ok(());
                    }
                }
            }

            let _ = sender.send(Ok(KeyContainer { keys }));
        }
    }

    Ok(())
}
