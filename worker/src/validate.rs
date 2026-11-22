//! Request bodies. Unknown fields are rejected so a client cannot set
//! server-owned columns such as `role` or `companyId` by slipping them in.

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use crate::authz::Role;
use crate::limits::{
    content_type_allowed, ALLOWED_EMBED_HOSTS, MAX_BODY_CHARS, MAX_CONTENT_JSON_BYTES,
    MAX_UPLOAD_BYTES,
};

/// Why a request body was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidInput {
    /// Field name, or `body` when the JSON itself is wrong.
    pub field: &'static str,
    /// A short explanation safe to show in the form.
    pub message: &'static str,
}

/// Start enrollment or recovery. This does not create a session.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmailStart {
    /// Address that receives the link.
    pub email: String,
    /// Shown on the account. Required for enrollment, ignored for recovery.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Browser ceremony posted with the email token or an existing account.
/// Body for a page opened from an enrollment or recovery link.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EmailLink {
    /// Raw token from the email link.
    pub token: String,
    /// Name to store. Required when the link is for enrollment.
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CeremonyBody {
    /// Email token. Absent for an ordinary sign-in.
    #[serde(default)]
    pub token: Option<String>,
    /// Account email. Required for sign-in.
    #[serde(default)]
    pub email: Option<String>,
    /// Name stored on a new account.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Credential id, base64url.
    pub credential_id: String,
    /// `clientDataJSON`, base64url. Serde's camelCase rename would emit
    /// `clientDataJson`, which is not the WebAuthn field name.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// `authenticatorData`, base64url.
    pub authenticator_data: String,
    /// Assertion signature, base64url. Empty for a new passkey.
    #[serde(default)]
    pub signature: Option<String>,
    /// SPKI from `getPublicKey()`, base64url. Required for a new passkey.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Create a company. The caller becomes its admin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NewCompany {
    /// Company name people see in the list.
    pub name: String,
}

/// Add someone who already has an account.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NewMember {
    /// Account email.
    pub email: String,
    /// `admin` or `member`.
    pub role: Role,
}

/// Rename a company.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompanyName {
    /// Replacement name.
    pub name: String,
}

/// Create or rename a Space.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpaceWrite {
    /// Display name.
    pub name: String,
    /// Optional short description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional slug. Generated from the name when omitted on create.
    #[serde(default)]
    pub slug: Option<String>,
}

/// Create or replace a Page's TipTap document (ADR 0011).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArticleWrite {
    /// Page title.
    pub title: String,
    /// TipTap JSON document.
    pub content: Value,
    /// Space that owns a new page. Required on create; ignored on update.
    #[serde(default)]
    pub space_id: Option<String>,
    /// Parent page for a new nested page.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Client's last-seen `updatedAt`. Required on update for conflict checks.
    #[serde(default)]
    pub expected_updated_at: Option<i64>,
}

/// Reparent or reorder a Page inside its Space.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArticleMove {
    /// New parent page, or omit/null for a root page.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Lexicographic order among siblings.
    pub position: String,
}

/// Checks an email address shape without promising the mailbox exists.
pub fn require_email(email: &str) -> Result<String, InvalidInput> {
    let email = email.trim().to_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return Err(InvalidInput {
            field: "email",
            message: "Enter an email address.",
        });
    };
    if local.is_empty()
        || domain.len() < 3
        || !domain.contains('.')
        || email.len() > 200
        || email.chars().any(char::is_whitespace)
    {
        return Err(InvalidInput {
            field: "email",
            message: "Enter an email address.",
        });
    }
    Ok(email)
}

/// Checks a display name.
pub fn require_display_name(name: &str) -> Result<String, InvalidInput> {
    let name = name.trim();
    let len = name.chars().count();
    if !(1..=80).contains(&len) {
        return Err(InvalidInput {
            field: "displayName",
            message: "Use 1 to 80 characters.",
        });
    }
    Ok(name.to_string())
}

/// Checks a company or similar short label.
pub fn require_label(field: &'static str, name: &str, max: usize) -> Result<String, InvalidInput> {
    let name = name.trim();
    let len = name.chars().count();
    if len < 1 || len > max {
        return Err(InvalidInput {
            field,
            message: "Use a shorter name.",
        });
    }
    Ok(name.to_string())
}

/// Checks or builds a Space slug.
pub fn require_slug(field: &'static str, slug: &str) -> Result<String, InvalidInput> {
    let slug = slug.trim().to_lowercase();
    if slug.is_empty() || slug.len() > 80 {
        return Err(InvalidInput {
            field,
            message: "Use a shorter slug.",
        });
    }
    if !slug
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        || slug.starts_with('-')
        || slug.ends_with('-')
        || slug.contains("--")
    {
        return Err(InvalidInput {
            field,
            message: "Use lowercase letters, numbers, and single hyphens.",
        });
    }
    Ok(slug)
}

/// Builds a slug from a Space name.
pub fn slug_from_name(name: &str) -> String {
    let mut out = String::new();
    let mut pending_hyphen = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_hyphen && !out.is_empty() {
                out.push('-');
            }
            pending_hyphen = false;
            out.push(ch.to_ascii_lowercase());
        } else if !out.is_empty() {
            pending_hyphen = true;
        }
    }
    if out.is_empty() {
        out.push_str("space");
    }
    out.truncate(80);
    out.trim_matches('-').to_string()
}

/// Validates TipTap JSON, derives FTS plain text, and returns serialized JSON.
pub fn require_page_content(
    title: &str,
    content: &Value,
) -> Result<(String, String, String), InvalidInput> {
    let title = require_label("title", title, 200)?;
    if !content.is_object() {
        return Err(InvalidInput {
            field: "content",
            message: "The page content is invalid.",
        });
    }
    let serialized = serde_json::to_string(content).map_err(|_| InvalidInput {
        field: "content",
        message: "The page content is invalid.",
    })?;
    if serialized.len() > MAX_CONTENT_JSON_BYTES {
        return Err(InvalidInput {
            field: "content",
            message: "The page is too long.",
        });
    }
    check_embeds(content)?;
    let body = plain_text_from_json(content);
    if body.chars().count() > MAX_BODY_CHARS {
        return Err(InvalidInput {
            field: "content",
            message: "The page is too long.",
        });
    }
    Ok((title, serialized, body))
}

/// Collects string leaves from TipTap JSON for FTS5.
pub fn plain_text_from_json(value: &Value) -> String {
    let mut parts = Vec::new();
    walk_strings(value, &mut parts);
    parts.join(" ")
}

fn walk_strings(value: &Value, parts: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                walk_strings(item, parts);
            }
        }
        Value::Object(map) => {
            // TipTap text nodes use `text`. Code/mermaid sources often live there too.
            if let Some(Value::String(text)) = map.get("text") {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    parts.push(trimmed.to_string());
                }
            }
            if let Some(child) = map.get("content") {
                walk_strings(child, parts);
            }
            if let Some(Value::Object(attrs)) = map.get("attrs") {
                for key in ["title", "label", "alt"] {
                    if let Some(Value::String(text)) = attrs.get(key) {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            parts.push(trimmed.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn check_embeds(value: &Value) -> Result<(), InvalidInput> {
    match value {
        Value::Array(items) => {
            for item in items {
                check_embeds(item)?;
            }
        }
        Value::Object(map) => {
            if map.get("type").and_then(Value::as_str) == Some("embed") {
                let attrs = map.get("attrs").and_then(Value::as_object);
                let url = attrs
                    .and_then(|attrs| attrs.get("src").or_else(|| attrs.get("url")))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                require_embed_url(url)?;
            }
            for child in map.values() {
                check_embeds(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Checks an embed URL against the allowlisted hosts.
pub fn require_embed_url(url: &str) -> Result<String, InvalidInput> {
    let url = url.trim();
    if url.is_empty() || url.len() > 2000 || url.chars().any(|ch| ch.is_whitespace() || ch == '\\')
    {
        return Err(InvalidInput {
            field: "content",
            message: "That embed link is not allowed.",
        });
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(InvalidInput {
            field: "content",
            message: "That embed link is not allowed.",
        });
    };
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_port
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() || !ALLOWED_EMBED_HOSTS.contains(&host.as_str()) {
        return Err(InvalidInput {
            field: "content",
            message: "That embed link is not allowed.",
        });
    }
    Ok(url.to_string())
}

/// Checks a Space description.
pub fn require_description(description: &str) -> Result<String, InvalidInput> {
    let description = description.trim();
    if description.chars().count() > 500 {
        return Err(InvalidInput {
            field: "description",
            message: "Use a shorter description.",
        });
    }
    Ok(description.to_string())
}

/// Checks a move position token.
pub fn require_position(position: &str) -> Result<String, InvalidInput> {
    let position = position.trim();
    let len = position.chars().count();
    if !(1..=64).contains(&len) {
        return Err(InvalidInput {
            field: "position",
            message: "Use a shorter position.",
        });
    }
    Ok(position.to_string())
}

/// Checks an upload before it is written to R2.
pub fn require_upload(
    file_name: &str,
    content_type: &str,
    byte_size: usize,
) -> Result<String, InvalidInput> {
    if byte_size == 0 || byte_size > MAX_UPLOAD_BYTES {
        return Err(InvalidInput {
            field: "file",
            message: "Files must be 10 MB or smaller.",
        });
    }
    if !content_type_allowed(content_type) {
        return Err(InvalidInput {
            field: "file",
            message: "Use a PNG, JPEG, WebP, PDF, or text file.",
        });
    }
    let file_name = file_name.trim().replace(['\r', '\n', '"', '\\'], "");
    let len = file_name.chars().count();
    if !(1..=200).contains(&len) {
        return Err(InvalidInput {
            field: "file",
            message: "Use a file name of 1 to 200 characters.",
        });
    }
    Ok(file_name)
}

/// Decodes a base64url field from a ceremony body.
pub fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>, InvalidInput> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim().as_bytes())
        .map_err(|_| InvalidInput {
            field,
            message: "The passkey response was incomplete.",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_body_accepts_the_webauthn_field_name() {
        let parsed = serde_json::from_str::<CeremonyBody>(
            r#"{"credentialId":"cred","clientDataJSON":"data","authenticatorData":"auth"}"#,
        )
        .expect("clientDataJSON is the name the browser sends");
        assert_eq!(parsed.client_data_json, "data");
    }

    #[test]
    fn article_write_rejects_a_company_id_field() {
        let parsed = serde_json::from_str::<ArticleWrite>(
            r#"{"title":"Hello","content":{"type":"doc","content":[]},"companyId":"other"}"#,
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn page_content_derives_plain_text_and_rejects_bad_embeds() {
        let content = serde_json::json!({
            "type": "doc",
            "content": [{
                "type": "paragraph",
                "content": [{"type": "text", "text": "Hello"}]
            }]
        });
        let (_, json, body) = require_page_content("Title", &content).unwrap();
        assert!(json.contains("Hello"));
        assert_eq!(body, "Hello");

        let bad = serde_json::json!({
            "type": "doc",
            "content": [{
                "type": "embed",
                "attrs": {"src": "https://evil.example/x"}
            }]
        });
        assert!(require_page_content("Title", &bad).is_err());
        assert!(require_embed_url("https://www.youtube.com/embed/abc").is_ok());
        assert!(require_embed_url("http://www.youtube.com/embed/abc").is_err());
    }

    #[test]
    fn slug_from_name_lowercases_and_hyphenates() {
        assert_eq!(slug_from_name("  Eng Docs! "), "eng-docs");
        assert_eq!(require_slug("slug", "eng-docs").unwrap(), "eng-docs");
        assert!(require_slug("slug", "Eng Docs").is_err());
    }

    #[test]
    fn member_write_rejects_an_unknown_role_carrier() {
        let parsed = serde_json::from_str::<NewMember>(
            r#"{"email":"a@example.com","role":"member","owner":true}"#,
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn upload_rejects_html() {
        let result = require_upload("notes.html", "text/html", 12);
        assert!(result.is_err());
    }

    #[test]
    fn upload_accepts_a_pdf() {
        let name = require_upload("policy.pdf", "application/pdf", 12).unwrap();
        assert_eq!(name, "policy.pdf");
    }
}
