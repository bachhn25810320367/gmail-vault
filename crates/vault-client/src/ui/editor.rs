use chrono::Utc;
use vault_core::Account;

#[derive(Debug, Clone)]
pub struct EditorDraft {
    pub account: Account,
    pub original_password: String,
    pub is_new: bool,
}

impl Default for EditorDraft {
    fn default() -> Self {
        Self::new()
    }
}

impl EditorDraft {
    pub fn new() -> Self {
        Self {
            account: Account::new("", ""),
            original_password: String::new(),
            is_new: true,
        }
    }

    pub fn from_account(account: &Account) -> Self {
        Self {
            account: account.clone(),
            original_password: account.password.clone(),
            is_new: false,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.account.validate().map_err(|e| e.to_string())
    }

    pub fn into_account(mut self) -> Account {
        self.account.updated_at = Utc::now();
        self.account
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::Account;

    #[test]
    fn draft_commits_changes() {
        let a = Account::new("a@b.co", "p");
        let mut d = EditorDraft::from_account(&a);
        d.account.notes = Some("ghi chú".into());
        let out = d.into_account();
        assert_eq!(out.notes.as_deref(), Some("ghi chú"));
        assert_eq!(out.id, a.id);
    }

    #[test]
    fn draft_rejects_empty_email() {
        let d = EditorDraft::new();
        assert!(d.validate().is_err());
    }
}
