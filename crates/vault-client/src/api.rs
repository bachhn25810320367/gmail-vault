use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vault_core::{KdfParams, WrappedKey};

use crate::platform;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("{message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },
    #[error("unauthorized")]
    Unauthorized,
}

#[derive(Serialize)]
pub struct RegisterRequest {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "vault_core::codec::base64")]
    pub auth_key: Vec<u8>,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    pub recovery_wrapped_key: WrappedKey,
    #[serde(with = "vault_core::codec::base64")]
    pub recovery_auth_key: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    #[serde(default)]
    pub recovery_wrapped_key: Option<WrappedKey>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PreloginResponse {
    pub kdf: KdfParams,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct KeysResponse {
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    #[serde(default)]
    pub recovery_wrapped_key: Option<WrappedKey>,
}

#[allow(dead_code)]
#[derive(Serialize)]
pub struct PutKeysRequest {
    pub kdf: KdfParams,
    pub wrapped_key: WrappedKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKey>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "vault_core::codec::base64_option"
    )]
    pub recovery_auth_key: Option<Vec<u8>>,
}

fn url_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[derive(Clone)]
pub struct VaultApi {
    base_url: String,
    http: reqwest::Client,
    access: Arc<Mutex<Option<String>>>,
    server_url: String,
    email: Arc<Mutex<String>>,
}

impl VaultApi {
    pub fn new(server_url: &str) -> Self {
        let trimmed = server_url.trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            base_url: trimmed.clone(),
            http,
            access: Arc::new(Mutex::new(None)),
            server_url: trimmed,
            email: Arc::new(Mutex::new(String::new())),
        }
    }

    #[allow(dead_code)]
    pub fn set_email(&self, email: &str) {
        let mut guard = self.email.lock().unwrap_or_else(|e| e.into_inner());
        *guard = email.to_string();
    }

    pub fn store_tokens(&self, email: &str, response: &AuthResponse) -> Result<(), ApiError> {
        *self.access.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(response.access_token.clone());
        platform::save_refresh(&self.server_url, email, &response.refresh_token)
            .map_err(ApiError::Network)?;
        *self.email.lock().unwrap_or_else(|e| e.into_inner()) = email.to_string();
        Ok(())
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        auth: bool,
    ) -> Result<reqwest::Response, ApiError> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.request(method, &url);
        if auth {
            let access = self.access.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(token) = access {
                req = req.bearer_auth(token);
            }
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| ApiError::Network(e.to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }
        if !status.is_success() {
            let status_code = status.as_u16();
            let text = resp.text().await.unwrap_or_default();
            if let Ok(err_payload) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(err_obj) = err_payload.get("error") {
                    let code = err_obj
                        .get("code")
                        .and_then(|c| c.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let message = err_obj
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or(&text)
                        .to_string();
                    return Err(ApiError::Server {
                        status: status_code,
                        code,
                        message,
                    });
                }
            }
            return Err(ApiError::Server {
                status: status_code,
                code: "unknown".to_string(),
                message: if text.is_empty() {
                    format!("HTTP {status_code}")
                } else {
                    text
                },
            });
        }
        Ok(resp)
    }

    async fn send_with_retry(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, ApiError> {
        match self.send(method.clone(), path, body.clone(), true).await {
            Ok(resp) => Ok(resp),
            Err(ApiError::Unauthorized) => {
                self.refresh().await?;
                self.send(method, path, body, true).await
            }
            Err(e) => Err(e),
        }
    }

    #[allow(dead_code)]
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, ApiError> {
        let encoded_email = url_encode(email);
        let path = format!("/v1/auth/kdf?email={encoded_email}");
        let resp = self.send(reqwest::Method::GET, &path, None, false).await?;
        resp.json().await.map_err(|e| ApiError::Network(e.to_string()))
    }

    pub async fn register(&self, req: &RegisterRequest) -> Result<AuthResponse, ApiError> {
        let body = serde_json::to_value(req).map_err(|e| ApiError::Network(e.to_string()))?;
        let resp = self
            .send(reqwest::Method::POST, "/v1/auth/register", Some(body), false)
            .await?;
        let auth_resp: AuthResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        self.store_tokens(&req.email, &auth_resp)?;
        Ok(auth_resp)
    }

    #[allow(dead_code)]
    pub async fn login(&self, email: &str, auth_key: &[u8]) -> Result<AuthResponse, ApiError> {
        let body = serde_json::json!({
            "email": email,
            "auth_key": vault_core::codec::encode(auth_key),
        });
        let resp = self
            .send(reqwest::Method::POST, "/v1/auth/login", Some(body), false)
            .await?;
        let auth_resp: AuthResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        self.store_tokens(email, &auth_resp)?;
        Ok(auth_resp)
    }

    #[allow(dead_code)]
    pub async fn recover_login(
        &self,
        email: &str,
        recovery_auth_key: &[u8],
    ) -> Result<AuthResponse, ApiError> {
        let body = serde_json::json!({
            "email": email,
            "recovery_auth_key": vault_core::codec::encode(recovery_auth_key),
        });
        let resp = self
            .send(
                reqwest::Method::POST,
                "/v1/auth/recover/login",
                Some(body),
                false,
            )
            .await?;
        let auth_resp: AuthResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        self.store_tokens(email, &auth_resp)?;
        Ok(auth_resp)
    }

    #[allow(dead_code)]
    pub async fn refresh(&self) -> Result<AuthResponse, ApiError> {
        let email = self.email.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if email.is_empty() {
            return Err(ApiError::Unauthorized);
        }
        let refresh_token = platform::load_refresh(&self.server_url, &email)
            .map_err(ApiError::Network)?
            .ok_or(ApiError::Unauthorized)?;
        let body = serde_json::json!({
            "refresh_token": refresh_token,
        });
        let resp = self
            .send(reqwest::Method::POST, "/v1/auth/refresh", Some(body), false)
            .await?;
        let auth_resp: AuthResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        self.store_tokens(&email, &auth_resp)?;
        Ok(auth_resp)
    }

    #[allow(dead_code)]
    pub async fn authorized_get(&self, path: &str) -> Result<reqwest::Response, ApiError> {
        self.send_with_retry(reqwest::Method::GET, path, None).await
    }

    #[allow(dead_code)]
    pub async fn authorized_put(
        &self,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, ApiError> {
        self.send_with_retry(reqwest::Method::PUT, path, body).await
    }

    #[allow(dead_code)]
    pub async fn get_keys(&self) -> Result<KeysResponse, ApiError> {
        let resp = self.authorized_get("/v1/keys").await?;
        resp.json().await.map_err(|e| ApiError::Network(e.to_string()))
    }

    #[allow(dead_code)]
    pub async fn put_keys(&self, req: &PutKeysRequest) -> Result<(), ApiError> {
        let body = serde_json::to_value(req).map_err(|e| ApiError::Network(e.to_string()))?;
        let _ = self.authorized_put("/v1/keys", Some(body)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::create_vault;

    #[test]
    fn register_request_uses_base64_strings() {
        let nv = create_vault("password-123").unwrap();
        let req = RegisterRequest {
            user_id: nv.user_id,
            email: "owner@example.com".into(),
            auth_key: nv.auth_key.to_vec(),
            kdf: nv.kdf.clone(),
            wrapped_key: nv.wrapped_key.clone(),
            recovery_wrapped_key: nv.recovery.wrapped_key.clone(),
            recovery_auth_key: nv.recovery.auth_key.to_vec(),
        };
        let value = serde_json::to_value(&req).unwrap();
        assert!(value["auth_key"].is_string());
        assert!(value["kdf"]["salt"].is_string());
        assert!(value["wrapped_key"]["nonce"].is_string());
    }
}
