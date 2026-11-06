pub mod codec;
pub mod crypto;
pub mod error;
pub mod model;

pub use crypto::{
    EncryptedRecord, KdfParams, NewVault, RecoveryMaterial, UnlockedVault, WrappedKey,
    create_vault, format_recovery_code, parse_recovery_code, recover_vault, unwrap_vault_key,
};
pub use error::{CoreError, Result};
pub use model::{Account, AccountStatus, Money, PasswordHistoryEntry, Plan};
