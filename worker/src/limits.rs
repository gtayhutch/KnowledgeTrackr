//! Product limits enforced by the API and recorded in the local security notes.

/// Absolute session lifetime. Logout and expiry both end access.
pub const SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// How long an emailed token or passkey challenge stays usable.
pub const CHALLENGE_TTL_MS: i64 = 15 * 60 * 1000;

/// Membership changes require a session newer than this window.
pub const REAUTH_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Enrollment and recovery messages allowed for one address each hour.
pub const EMAIL_CHALLENGES_PER_HOUR: i64 = 5;

/// Passkey ceremony starts allowed for one address each hour.
pub const WEBAUTHN_CHALLENGES_PER_HOUR: i64 = 20;

/// Largest accepted attachment, in bytes.
pub const MAX_UPLOAD_BYTES: usize = 10 * 1024 * 1024;

/// Largest accepted TipTap JSON document, in UTF-8 bytes.
pub const MAX_CONTENT_JSON_BYTES: usize = 200 * 1024;

/// Largest derived plain-text body, in Unicode scalar values.
pub const MAX_BODY_CHARS: usize = 100_000;

/// Hosts allowed inside embed nodes in page content.
pub const ALLOWED_EMBED_HOSTS: [&str; 6] = [
    "www.youtube.com",
    "youtube.com",
    "www.loom.com",
    "loom.com",
    "www.figma.com",
    "figma.com",
];

/// Content types an attachment may use.
pub const ALLOWED_CONTENT_TYPES: [&str; 6] = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "application/pdf",
    "text/plain",
    "text/markdown",
];

/// Returns whether `content_type` is an allowed attachment type.
pub fn content_type_allowed(content_type: &str) -> bool {
    ALLOWED_CONTENT_TYPES.contains(&content_type)
}
