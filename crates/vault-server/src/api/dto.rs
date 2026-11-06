use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod b64 {
    use ::base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod b64_opt {
    use ::base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let value: Option<String> = Option::deserialize(d)?;
        value
            .map(|s| STANDARD.decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfDto {
    pub algo: String,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyDto {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    pub recovery_wrapped_key: WrappedKeyDto,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RecoverLoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: usize,
    pub kdf: KdfDto,
    pub wrapped_key: WrappedKeyDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_key: Option<WrappedKeyDto>,
}
