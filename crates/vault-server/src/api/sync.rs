use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use sqlx::{Sqlite, Transaction};
use uuid::Uuid;

use crate::AppState;
use crate::auth::AuthUser;
use crate::error::AppError;

const DEFAULT_LIMIT: u32 = 500;
const MAX_LIMIT: u32 = 1000;
const MAX_BATCH: usize = 200;
const MAX_PAYLOAD: usize = 64 * 1024;

const RECORD_COLUMNS: &str = "id, revision, change_seq, updated_at, deleted, nonce, payload";

type RecordTuple = (String, i64, i64, i64, i64, Option<Vec<u8>>, Option<Vec<u8>>);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sync/changes", get(changes))
        .route("/sync/push", post(push))
}

#[derive(Deserialize)]
pub struct ChangesQuery {
    pub since: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Serialize)]
pub struct RecordDto {
    pub id: Uuid,
    pub revision: u64,
    pub change_seq: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::api::dto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::api::dto::b64")]
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PushItemDto {
    pub id: Uuid,
    pub base_revision: u64,
    pub updated_at: i64,
    pub deleted: bool,
    #[serde(with = "crate::api::dto::b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "crate::api::dto::b64")]
    pub payload: Vec<u8>,
}

#[derive(Deserialize)]
pub struct PushRequest {
    pub records: Vec<PushItemDto>,
}

#[derive(Serialize)]
pub struct AcceptedDto {
    pub id: Uuid,
    pub revision: u64,
    pub change_seq: u64,
}

#[derive(Serialize)]
pub struct ConflictDto {
    pub id: Uuid,
    pub server: RecordDto,
}

#[derive(Serialize)]
pub struct PushResponse {
    pub accepted: Vec<AcceptedDto>,
    pub conflicts: Vec<ConflictDto>,
}

#[derive(Serialize)]
pub struct PullResponse {
    pub items: Vec<RecordDto>,
    pub next_since: u64,
    pub has_more: bool,
}

fn internal(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

fn record_from_row(row: RecordTuple) -> Result<RecordDto, AppError> {
    let (id, revision, change_seq, updated_at, deleted, nonce, payload) = row;
    Ok(RecordDto {
        id: Uuid::parse_str(&id).map_err(internal)?,
        revision: revision as u64,
        change_seq: change_seq as u64,
        updated_at,
        deleted: deleted != 0,
        nonce: nonce.unwrap_or_default(),
        payload: payload.unwrap_or_default(),
    })
}

async fn next_seq(tx: &mut Transaction<'_, Sqlite>, user_id: &str) -> Result<u64, AppError> {
    sqlx::query(
        "INSERT INTO user_seq(user_id, next_seq) VALUES(?, 1)
         ON CONFLICT(user_id) DO UPDATE SET next_seq = next_seq + 1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(internal)?;
    let seq: i64 = sqlx::query_scalar("SELECT next_seq FROM user_seq WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(internal)?;
    Ok(seq as u64)
}

async fn changes(
    user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<ChangesQuery>,
) -> Result<Json<PullResponse>, AppError> {
    let since = query.since.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let rows: Vec<RecordTuple> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM records
         WHERE user_id = ? AND change_seq > ? ORDER BY change_seq ASC LIMIT ?"
    ))
    .bind(user.user_id.to_string())
    .bind(since as i64)
    .bind((limit + 1) as i64)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let has_more = rows.len() > limit as usize;
    let mut items = Vec::new();
    for row in rows.into_iter().take(limit as usize) {
        items.push(record_from_row(row)?);
    }
    let next_since = items.last().map(|r| r.change_seq).unwrap_or(since);
    Ok(Json(PullResponse {
        items,
        next_since,
        has_more,
    }))
}

async fn push(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, AppError> {
    if req.records.len() > MAX_BATCH {
        return Err(AppError::PayloadTooLarge);
    }
    for item in &req.records {
        if item.payload.len() > MAX_PAYLOAD {
            return Err(AppError::PayloadTooLarge);
        }
        if !item.deleted && item.nonce.len() != 24 {
            return Err(AppError::BadRequest("nonce không hợp lệ".into()));
        }
    }

    let user_id = user.user_id.to_string();
    let mut tx = state.pool.begin().await.map_err(internal)?;
    let mut accepted = Vec::new();
    let mut conflicts = Vec::new();

    for item in req.records {
        let current: Option<(i64,)> =
            sqlx::query_as("SELECT revision FROM records WHERE user_id = ? AND id = ?")
                .bind(&user_id)
                .bind(item.id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(internal)?;
        let accepted_now = match &current {
            None => item.base_revision == 0,
            Some((revision,)) => *revision as u64 == item.base_revision,
        };

        if accepted_now {
            let seq = next_seq(&mut tx, &user_id).await? as i64;
            let revision = current.as_ref().map(|(r,)| r + 1).unwrap_or(1);
            let nonce = if item.deleted || item.nonce.is_empty() {
                None
            } else {
                Some(item.nonce.clone())
            };
            let payload = if item.deleted || item.payload.is_empty() {
                None
            } else {
                Some(item.payload.clone())
            };
            match &current {
                None => {
                    sqlx::query(
                        "INSERT INTO records(user_id, id, revision, change_seq, updated_at,
                                             deleted, nonce, payload)
                         VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&user_id)
                    .bind(item.id.to_string())
                    .bind(revision)
                    .bind(seq)
                    .bind(item.updated_at)
                    .bind(item.deleted as i64)
                    .bind(nonce)
                    .bind(payload)
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                }
                Some(_) => {
                    sqlx::query(
                        "UPDATE records SET revision = ?, change_seq = ?, updated_at = ?,
                                deleted = ?, nonce = ?, payload = ?
                         WHERE user_id = ? AND id = ?",
                    )
                    .bind(revision)
                    .bind(seq)
                    .bind(item.updated_at)
                    .bind(item.deleted as i64)
                    .bind(nonce)
                    .bind(payload)
                    .bind(&user_id)
                    .bind(item.id.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(internal)?;
                }
            }
            accepted.push(AcceptedDto {
                id: item.id,
                revision: revision as u64,
                change_seq: seq as u64,
            });
        } else {
            let row: RecordTuple = sqlx::query_as(&format!(
                "SELECT {RECORD_COLUMNS} FROM records WHERE user_id = ? AND id = ?"
            ))
            .bind(&user_id)
            .bind(item.id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
            conflicts.push(ConflictDto {
                id: item.id,
                server: record_from_row(row)?,
            });
        }
    }

    tx.commit().await.map_err(internal)?;
    Ok(Json(PushResponse {
        accepted,
        conflicts,
    }))
}
