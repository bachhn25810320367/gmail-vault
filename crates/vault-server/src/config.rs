use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub jwt_secret: Arc<Vec<u8>>,
    pub allow_registration: bool,
    pub max_body_bytes: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_map(|key| std::env::var(key).ok())
    }

    pub fn from_map(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let database_url = get("DATABASE_URL").ok_or("DATABASE_URL is required")?;
        let secret = get("JWT_SECRET").ok_or("JWT_SECRET is required")?;
        if secret.as_bytes().len() < 32 {
            return Err("JWT_SECRET must be at least 32 bytes".into());
        }
        let bind_addr = get("BIND_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .map_err(|e| format!("invalid BIND_ADDR: {e}"))?;
        let allow_registration = get("ALLOW_REGISTRATION")
            .map(|v| v == "true")
            .unwrap_or(false);
        let max_body_bytes = get("MAX_BODY_BYTES")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2 * 1024 * 1024);
        Ok(Self {
            bind_addr,
            database_url,
            jwt_secret: Arc::new(secret.into_bytes()),
            allow_registration,
            max_body_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_required_values() {
        let env = |k: &str| match k {
            "DATABASE_URL" => Some("sqlite:///tmp/vault.db".to_string()),
            "JWT_SECRET" => Some("0123456789abcdef0123456789abcdef".to_string()),
            _ => None,
        };
        let cfg = Config::from_map(env).unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(cfg.max_body_bytes, 2 * 1024 * 1024);
        assert!(!cfg.allow_registration);
    }

    #[test]
    fn rejects_short_jwt_secret() {
        let env = |k: &str| match k {
            "DATABASE_URL" => Some("sqlite::memory:".to_string()),
            "JWT_SECRET" => Some("short".to_string()),
            _ => None,
        };
        assert!(Config::from_map(env).is_err());
    }
}
