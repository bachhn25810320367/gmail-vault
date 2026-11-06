use unicode_normalization::UnicodeNormalization;
use vault_core::{Account, AccountStatus, Plan};

#[derive(Debug, Clone, Default)]
pub struct Filters {
    pub text: String,
    pub plan: Option<Plan>,
    pub status: Option<AccountStatus>,
    pub tag: Option<String>,
}

pub fn normalize_for_search(input: &str) -> String {
    input
        .to_lowercase()
        .replace('đ', "d")
        .nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

impl Filters {
    pub fn matches(&self, account: &Account) -> bool {
        if let Some(plan) = &self.plan
            && &account.plan != plan
        {
            return false;
        }
        if let Some(status) = &self.status
            && &account.status != status
        {
            return false;
        }
        if let Some(tag) = &self.tag
            && !account.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
        {
            return false;
        }
        let text = normalize_for_search(self.text.trim());
        if text.is_empty() {
            return true;
        }
        let haystack = normalize_for_search(&format!(
            "{} {} {}",
            account.email,
            account.notes.as_deref().unwrap_or_default(),
            account.tags.join(" ")
        ));
        haystack.contains(&text)
    }

    pub fn apply<'a>(&self, accounts: &'a [Account]) -> Vec<&'a Account> {
        accounts.iter().filter(|a| self.matches(a)).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Email,
    CreatedOn,
    Plan,
    Status,
    ExpiresOn,
    LastUsedOn,
    UpdatedAt,
}

#[derive(Debug, Clone, Copy)]
pub struct SortState {
    pub key: SortKey,
    pub descending: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            key: SortKey::Email,
            descending: false,
        }
    }
}

pub fn sort_accounts(rows: &mut [&Account], sort: &SortState) {
    rows.sort_by(|a, b| {
        let ord = match sort.key {
            SortKey::Email => a.normalized_email().cmp(&b.normalized_email()),
            SortKey::CreatedOn => a.created_on.cmp(&b.created_on),
            SortKey::Plan => a.plan.as_str().cmp(b.plan.as_str()),
            SortKey::Status => a.status.as_str().cmp(b.status.as_str()),
            SortKey::ExpiresOn => a.expires_on.cmp(&b.expires_on),
            SortKey::LastUsedOn => a.last_used_on.cmp(&b.last_used_on),
            SortKey::UpdatedAt => a.updated_at.cmp(&b.updated_at),
        };
        if sort.descending {
            ord.reverse()
        } else {
            ord
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Account, Plan};

    #[test]
    fn search_removes_vietnamese_diacritics() {
        assert_eq!(normalize_for_search("Đặng Văn"), "dang van");
        let mut a = Account::new("dang@example.com", "p");
        a.notes = Some("Tài khoản của Đặng".into());
        let f = Filters {
            text: "dang".into(),
            ..Default::default()
        };
        assert!(f.matches(&a));
        let f = Filters {
            text: "dang van".into(),
            ..Default::default()
        };
        assert!(!f.matches(&a));
    }

    #[test]
    fn filters_by_plan_status_and_tag() {
        let mut a = Account::new("a@b.co", "p");
        a.plan = Plan::Pro;
        a.tags = vec!["vip".into()];
        assert!(
            Filters {
                plan: Some(Plan::Pro),
                ..Default::default()
            }
            .matches(&a)
        );
        assert!(
            !Filters {
                plan: Some(Plan::Ultra),
                ..Default::default()
            }
            .matches(&a)
        );
        assert!(
            Filters {
                tag: Some("vip".into()),
                ..Default::default()
            }
            .matches(&a)
        );
    }
}
