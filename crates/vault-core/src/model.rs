use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

pub const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Plan {
    Free,
    Pro,
    Ultra,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    Active,
    Banned,
    Sold,
    Deleted,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    #[serde(with = "rust_decimal::serde::str")]
    pub amount: Decimal,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub changed_at: DateTime<Utc>,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub schema_version: u16,
    pub id: Uuid,
    pub email: String,
    pub password: String,
    pub created_on: Option<NaiveDate>,
    pub plan: Plan,
    pub status: AccountStatus,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub recovery_email: Option<String>,
    pub recovery_phone: Option<String>,
    pub totp_secret: Option<String>,
    pub expires_on: Option<NaiveDate>,
    pub price: Option<Money>,
    pub last_used_on: Option<NaiveDate>,
    pub use_count: u32,
    pub password_changed_on: Option<NaiveDate>,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub custom_fields: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Plan {
    pub fn as_str(&self) -> &'static str {
        match self {
            Plan::Free => "Free",
            Plan::Pro => "Pro",
            Plan::Ultra => "Ultra",
        }
    }
}

impl Default for Plan {
    fn default() -> Self {
        Plan::Free
    }
}

impl AccountStatus {
    pub fn as_str(&self) -> &str {
        match self {
            AccountStatus::Active => "Active",
            AccountStatus::Banned => "Banned",
            AccountStatus::Sold => "Sold",
            AccountStatus::Deleted => "Deleted",
            AccountStatus::Other(s) => s,
        }
    }
}

impl Default for AccountStatus {
    fn default() -> Self {
        AccountStatus::Active
    }
}

impl Money {
    pub fn new(amount: Decimal, currency: impl Into<String>) -> Self {
        Self {
            amount,
            currency: currency.into().to_uppercase(),
        }
    }
}

impl Account {
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            schema_version: SCHEMA_VERSION,
            id: Uuid::new_v4(),
            email: email.into(),
            password: password.into(),
            created_on: None,
            plan: Plan::Free,
            status: AccountStatus::Active,
            tags: Vec::new(),
            notes: None,
            recovery_email: None,
            recovery_phone: None,
            totp_secret: None,
            expires_on: None,
            price: None,
            last_used_on: None,
            use_count: 0,
            password_changed_on: None,
            password_history: Vec::new(),
            custom_fields: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn normalized_email(&self) -> String {
        self.email.trim().to_lowercase()
    }

    pub fn age_days(&self, today: NaiveDate) -> Option<i64> {
        self.created_on.map(|d| (today - d).num_days())
    }

    pub fn set_password(&mut self, new_password: String, now: DateTime<Utc>) {
        if new_password == self.password {
            return;
        }
        self.password_history.insert(
            0,
            PasswordHistoryEntry {
                changed_at: now,
                password: std::mem::replace(&mut self.password, new_password),
            },
        );
        self.password_history.truncate(5);
        self.password_changed_on = Some(now.date_naive());
        self.updated_at = now;
    }

    pub fn mark_used(&mut self, today: NaiveDate) {
        self.last_used_on = Some(today);
        self.use_count = self.use_count.saturating_add(1);
        self.updated_at = Utc::now();
    }

    pub fn validate(&self) -> Result<()> {
        let email = self.normalized_email();
        let mut parts = email.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.')
        {
            return Err(CoreError::Validation("email không hợp lệ".into()));
        }
        if self.password.is_empty() {
            return Err(CoreError::Validation("mật khẩu không được rỗng".into()));
        }
        if self.tags.len() > 50 {
            return Err(CoreError::Validation("tối đa 50 tag".into()));
        }
        if self
            .tags
            .iter()
            .any(|t| t.trim().is_empty() || t.len() > 40)
        {
            return Err(CoreError::Validation("tag không hợp lệ".into()));
        }
        if let Some(price) = &self.price {
            if price.amount < Decimal::ZERO {
                return Err(CoreError::Validation("giá không được âm".into()));
            }
            if price.currency.len() != 3 || !price.currency.chars().all(|c| c.is_ascii_uppercase())
            {
                return Err(CoreError::Validation(
                    "currency phải là 3 chữ in hoa".into(),
                ));
            }
        }
        if let (Some(created), Some(expires)) = (self.created_on, self.expires_on) {
            if expires < created {
                return Err(CoreError::Validation("ngày hết hạn trước ngày tạo".into()));
            }
        }
        if self.custom_fields.len() > 50 {
            return Err(CoreError::Validation("tối đa 50 custom field".into()));
        }
        if self.custom_fields.keys().any(|key| key.trim().is_empty()) {
            return Err(CoreError::Validation(
                "custom field key không được rỗng".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Days;

    #[test]
    fn new_account_has_defaults() {
        let a = Account::new(" User@Example.com ", "secret");
        assert_eq!(a.email, " User@Example.com ");
        assert_eq!(a.normalized_email(), "user@example.com");
        assert_eq!(a.plan, Plan::Free);
        assert_eq!(a.status, AccountStatus::Active);
        assert_eq!(a.schema_version, 1);
        assert_eq!(a.use_count, 0);
        assert!(a.password_history.is_empty());
        assert!(a.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_email() {
        let a = Account::new("not-an-email", "x");
        assert!(matches!(a.validate(), Err(CoreError::Validation(_))));
    }

    #[test]
    fn set_password_keeps_last_five() {
        let mut a = Account::new("a@b.co", "p0");
        for i in 1..=7 {
            a.set_password(format!("p{i}"), Utc::now());
        }
        assert_eq!(a.password_history.len(), 5);
        assert_eq!(a.password_history[0].password, "p6");
        assert_eq!(a.password_history[4].password, "p2");
        assert!(a.password_changed_on.is_some());
    }

    #[test]
    fn mark_used_updates_count_and_date() {
        let mut a = Account::new("a@b.co", "p");
        let today = NaiveDate::from_ymd_opt(2026, 11, 6).unwrap();
        a.mark_used(today);
        a.mark_used(today);
        assert_eq!(a.use_count, 2);
        assert_eq!(a.last_used_on, Some(today));
    }

    #[test]
    fn age_days_uses_created_on() {
        let mut a = Account::new("a@b.co", "p");
        let today = NaiveDate::from_ymd_opt(2026, 11, 6).unwrap();
        a.created_on = Some(today - Days::new(10));
        assert_eq!(a.age_days(today), Some(10));
        a.created_on = None;
        assert_eq!(a.age_days(today), None);
    }
}
