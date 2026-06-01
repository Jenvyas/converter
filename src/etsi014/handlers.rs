use axum::{
    Json, debug_handler,
    extract::{self, Path, Query, State},
};
use hyper::StatusCode;
use tokio::sync::oneshot;
use tracing::error;

use crate::etsi014::{E014ConverterRequest, E014ConverterRequestInner};

use super::models::{GetKey, GetKeyWithId, GetKeysWithId, KeyContainer};

use super::Etsi014State;
use super::models::Status;

#[debug_handler]
pub async fn get_status(State(state): State<Etsi014State>, Path(slave_sae_id): Path<String>) -> Result<Json<Status>, StatusCode> {
    let (tx, rx) = oneshot::channel();

    let req = E014ConverterRequestInner::Status(tx);

    let _ = state
        .converter_handle
        .send(E014ConverterRequest::new(req, state.sae_id, slave_sae_id))
        .await;

    rx.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.map(|a| a.into())
}

#[debug_handler]
pub async fn get_key(
    State(state): State<Etsi014State>,
    Path(slave_sae_id): Path<String>,
    Query(key_request): Query<GetKey>,
) -> Result<Json<KeyContainer>, StatusCode> {
    let (tx, rx) = oneshot::channel();

    let req = E014ConverterRequestInner::EncKey(tx, key_request.into());

    let _ = state
        .converter_handle
        .send(E014ConverterRequest::new(req, state.sae_id, slave_sae_id))
        .await;

    rx.await.map_err(|e| {
        error!("Sender dropped: {}",e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?.map(|a| a.into())
}

#[debug_handler]
pub async fn post_key(
    State(state): State<Etsi014State>,
    Path(slave_sae_id): Path<String>,
    extract::Json(payload): extract::Json<GetKey>,
) -> Result<Json<KeyContainer>, StatusCode> {
    let (tx, rx) = oneshot::channel();

    let req = E014ConverterRequestInner::EncKey(tx, payload.into());

    let _ = state
        .converter_handle
        .send(E014ConverterRequest::new(req, state.sae_id, slave_sae_id))
        .await;

    rx.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.map(|a| a.into())
}

pub async fn get_key_with_id(
    State(state): State<Etsi014State>,
    Path(master_sae_id): Path<String>,
    Query(key_id): Query<GetKeyWithId>,
) -> Result<Json<KeyContainer>, StatusCode> {
    let (tx, rx) = oneshot::channel();

    let req = E014ConverterRequestInner::DecKey(tx, GetKeysWithId { key_IDs: vec![key_id] });

    let _ = state
        .converter_handle
        .send(E014ConverterRequest::new(req, state.sae_id, master_sae_id))
        .await;

    rx.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.map(|a| a.into())
}

#[debug_handler]
pub async fn post_key_with_id(
    State(state): State<Etsi014State>,
    Path(master_sae_id): Path<String>,
    extract::Json(payload): extract::Json<GetKeysWithId>,
) -> Result<Json<KeyContainer>, StatusCode> {
    let (tx, rx) = oneshot::channel();

    let req = E014ConverterRequestInner::DecKey(tx, payload);

    let _ = state
        .converter_handle
        .send(E014ConverterRequest::new(req, state.sae_id, master_sae_id))
        .await;

    rx.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.map(|a| a.into())
}
