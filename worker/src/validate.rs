//! Request bodies. Unknown fields are rejected so a client cannot set
//! server-owned columns such as `role` or `companyId` by slipping them in.

use base64::Engine;
use serde::Deserialize;

use crate::authz::Role;
use crate::limits::{content_type_allowed, MAX_UPLOAD_BYTES};

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

/// Create or replace an article's text.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArticleWrite {
    /// Article title.
    pub title: String,
    /// Article body, markdown or plain text.
    pub body: String,
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

/// Checks article text lengths.
pub fn require_article(title: &str, body: &str) -> Result<(String, String), InvalidInput> {
    let title = require_label("title", title, 200)?;
    if body.chars().count() > 100_000 {
        return Err(InvalidInput {
            field: "body",
            message: "The article is too long.",
        });
    }
    Ok((title, body.to_string()))
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
            r#"{"title":"Hello","body":"Text","companyId":"other"}"#,
        );
        assert!(parsed.is_err());
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
