//! D1 queries. Callers authorize before invoking a write or a company read.

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{D1Database, Result};

use crate::authz::Role;

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn num(value: i64) -> JsValue {
    JsValue::from_f64(value as f64)
}

/// A user row.
#[derive(Debug, Deserialize)]
pub struct UserRow {
    /// Account id.
    pub id: String,
    /// Normalized email.
    pub email: String,
    /// Name shown in the product.
    pub display_name: String,
}

/// A session that is still usable. Expiry and revocation are filtered in SQL.
#[derive(Debug, Deserialize)]
pub struct SessionRow {
    /// Owning user.
    pub user_id: String,
    /// Creation time, unix milliseconds. Used for the reauthentication window.
    pub created_at: i64,
}

/// One company membership.
#[derive(Debug, Deserialize)]
pub struct MembershipRow {
    /// Company id.
    pub company_id: String,
    /// Company name.
    pub company_name: String,
    /// `admin` or `member`.
    pub role: String,
}

/// A Space inside a company (ADR 0008).
#[derive(Debug, Deserialize)]
pub struct SpaceRow {
    /// Space id.
    pub id: String,
    /// Owning company. Kept for callers that authorize against the row.
    #[allow(dead_code)]
    pub company_id: String,
    /// Display name.
    pub name: String,
    /// URL slug unique inside the company.
    pub slug: String,
    /// Optional short description.
    pub description: String,
    /// Archive time, when set. Present for restore checks.
    #[allow(dead_code)]
    pub archived_at: Option<i64>,
}

/// A Page row. Stored in the `articles` table until a later rename migration.
#[derive(Debug, Deserialize)]
pub struct ArticleRow {
    /// Page id.
    pub id: String,
    /// Space that owns the page.
    pub space_id: String,
    /// Parent page id, when nested.
    pub parent_id: Option<String>,
    /// Lexicographic order among siblings.
    pub position: String,
    /// Optional icon token.
    pub icon: Option<String>,
    /// Title.
    pub title: String,
    /// Body.
    pub body: String,
    /// Author account id.
    pub author_id: String,
    /// Last edit, unix milliseconds.
    pub updated_at: i64,
}

/// Attachment metadata needed to stream the object. The query already
/// constrains the row to one company.
#[derive(Debug, Deserialize)]
pub struct AttachmentRow {
    /// R2 object key.
    pub object_key: String,
    /// Original file name.
    pub file_name: String,
    /// Stored content type.
    pub content_type: String,
}

/// Counts recent email challenges for rate limiting.
pub async fn count_email_challenges(db: &D1Database, email: &str, since_ms: i64) -> Result<i64> {
    let row = db
        .prepare(
            "SELECT COUNT(*) AS count FROM email_challenges
             WHERE email = ?1 AND created_at >= ?2",
        )
        .bind(&[text(email), num(since_ms)])?
        .first::<CountRow>(None)
        .await?;
    Ok(row.map(|row| row.count).unwrap_or(0))
}

/// Inserts an email token hash. The raw token is only sent by email.
pub async fn insert_email_challenge(
    db: &D1Database,
    id: &str,
    email: &str,
    purpose: &str,
    token_hash: &str,
    now_ms: i64,
    expires_at: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO email_challenges
         (id, email, purpose, token_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&[
        text(id),
        text(email),
        text(purpose),
        text(token_hash),
        num(now_ms),
        num(expires_at),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Returns the email for a live token without consuming it.
pub async fn find_email_challenge(
    db: &D1Database,
    purpose: &str,
    token_hash: &str,
    now_ms: i64,
) -> Result<Option<String>> {
    let row = db
        .prepare(
            "SELECT email FROM email_challenges
             WHERE purpose = ?1 AND token_hash = ?2
               AND consumed_at IS NULL AND expires_at > ?3",
        )
        .bind(&[text(purpose), text(token_hash), num(now_ms)])?
        .first::<EmailRow>(None)
        .await?;
    Ok(row.map(|row| row.email))
}

/// Consumes a matching unexpired token and returns its email.
pub async fn consume_email_challenge(
    db: &D1Database,
    purpose: &str,
    token_hash: &str,
    now_ms: i64,
) -> Result<Option<String>> {
    let row = db
        .prepare(
            "SELECT email FROM email_challenges
             WHERE purpose = ?1 AND token_hash = ?2
               AND consumed_at IS NULL AND expires_at > ?3",
        )
        .bind(&[text(purpose), text(token_hash), num(now_ms)])?
        .first::<EmailRow>(None)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    db.prepare(
        "UPDATE email_challenges SET consumed_at = ?1
         WHERE token_hash = ?2 AND consumed_at IS NULL",
    )
    .bind(&[num(now_ms), text(token_hash)])?
    .run()
    .await?;
    Ok(Some(row.email))
}

/// Counts recent passkey challenges for rate limiting.
pub async fn count_webauthn_challenges(db: &D1Database, email: &str, since_ms: i64) -> Result<i64> {
    let row = db
        .prepare(
            "SELECT COUNT(*) AS count FROM webauthn_challenges
             WHERE email = ?1 AND created_at >= ?2",
        )
        .bind(&[text(email), num(since_ms)])?
        .first::<CountRow>(None)
        .await?;
    Ok(row.map(|row| row.count).unwrap_or(0))
}

/// Stores a passkey challenge.
pub async fn insert_webauthn_challenge(
    db: &D1Database,
    id: &str,
    email: &str,
    purpose: &str,
    challenge: &str,
    now_ms: i64,
    expires_at: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO webauthn_challenges
         (id, email, purpose, challenge, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&[
        text(id),
        text(email),
        text(purpose),
        text(challenge),
        num(now_ms),
        num(expires_at),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Consumes a passkey challenge issued for `email` and `purpose`.
pub async fn consume_webauthn_challenge(
    db: &D1Database,
    email: &str,
    purpose: &str,
    challenge: &str,
    now_ms: i64,
) -> Result<bool> {
    let row = db
        .prepare(
            "SELECT id FROM webauthn_challenges
             WHERE email = ?1 AND purpose = ?2 AND challenge = ?3
               AND consumed_at IS NULL AND expires_at > ?4",
        )
        .bind(&[text(email), text(purpose), text(challenge), num(now_ms)])?
        .first::<IdRow>(None)
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    db.prepare("UPDATE webauthn_challenges SET consumed_at = ?1 WHERE id = ?2")
        .bind(&[num(now_ms), text(&row.id)])?
        .run()
        .await?;
    Ok(true)
}

/// Inserts a new account.
pub async fn insert_user(
    db: &D1Database,
    id: &str,
    email: &str,
    display_name: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare("INSERT INTO users (id, email, display_name, created_at) VALUES (?1, ?2, ?3, ?4)")
        .bind(&[text(id), text(email), text(display_name), num(now_ms)])?
        .run()
        .await?;
    Ok(())
}

/// Finds an account by normalized email.
pub async fn find_user_by_email(db: &D1Database, email: &str) -> Result<Option<UserRow>> {
    db.prepare("SELECT id, email, display_name FROM users WHERE email = ?1")
        .bind(&[text(email)])?
        .first(None)
        .await
}

/// Finds an account by id.
pub async fn find_user(db: &D1Database, id: &str) -> Result<Option<UserRow>> {
    db.prepare("SELECT id, email, display_name FROM users WHERE id = ?1")
        .bind(&[text(id)])?
        .first(None)
        .await
}

/// Stores a passkey.
pub async fn insert_passkey(
    db: &D1Database,
    credential_id: &str,
    user_id: &str,
    public_key_spki: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO passkey_credentials
         (credential_id, user_id, public_key_spki, signature_counter, created_at)
         VALUES (?1, ?2, ?3, 0, ?4)",
    )
    .bind(&[
        text(credential_id),
        text(user_id),
        text(public_key_spki),
        num(now_ms),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Removes every passkey for a user during recovery.
pub async fn delete_passkeys(db: &D1Database, user_id: &str) -> Result<()> {
    db.prepare("DELETE FROM passkey_credentials WHERE user_id = ?1")
        .bind(&[text(user_id)])?
        .run()
        .await?;
    Ok(())
}

/// A stored passkey row.
#[derive(Debug, Deserialize)]
pub struct PasskeyRow {
    /// Credential id, base64url.
    pub credential_id: String,
    /// SPKI, base64url.
    pub public_key_spki: String,
    /// Last counter.
    pub signature_counter: i64,
}

/// Loads one passkey for a user.
pub async fn find_passkey(
    db: &D1Database,
    user_id: &str,
    credential_id: &str,
) -> Result<Option<PasskeyRow>> {
    db.prepare(
        "SELECT credential_id, public_key_spki, signature_counter
         FROM passkey_credentials WHERE user_id = ?1 AND credential_id = ?2",
    )
    .bind(&[text(user_id), text(credential_id)])?
    .first(None)
    .await
}

/// Lists credential ids so the browser can offer them.
pub async fn list_credential_ids(db: &D1Database, user_id: &str) -> Result<Vec<String>> {
    let fetched = db
        .prepare("SELECT credential_id FROM passkey_credentials WHERE user_id = ?1")
        .bind(&[text(user_id)])?
        .all()
        .await?;
    let rows: Vec<IdNameRow> = fetched.results()?;
    Ok(rows.into_iter().map(|row| row.credential_id).collect())
}

/// Updates the signature counter after a successful sign-in.
pub async fn set_counter(db: &D1Database, credential_id: &str, counter: u32) -> Result<()> {
    db.prepare("UPDATE passkey_credentials SET signature_counter = ?1 WHERE credential_id = ?2")
        .bind(&[num(i64::from(counter)), text(credential_id)])?
        .run()
        .await?;
    Ok(())
}

/// Creates a session.
pub async fn insert_session(
    db: &D1Database,
    id: &str,
    user_id: &str,
    now_ms: i64,
    expires_at: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&[text(id), text(user_id), num(now_ms), num(expires_at)])?
    .run()
    .await?;
    Ok(())
}

/// Loads a session that is still usable.
pub async fn find_live_session(
    db: &D1Database,
    id: &str,
    now_ms: i64,
) -> Result<Option<SessionRow>> {
    db.prepare(
        "SELECT user_id, created_at FROM sessions
         WHERE id = ?1 AND revoked_at IS NULL AND expires_at > ?2",
    )
    .bind(&[text(id), num(now_ms)])?
    .first(None)
    .await
}

/// Revokes a session.
pub async fn revoke_session(db: &D1Database, id: &str, now_ms: i64) -> Result<()> {
    db.prepare("UPDATE sessions SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL")
        .bind(&[num(now_ms), text(id)])?
        .run()
        .await?;
    Ok(())
}

/// Creates a company, an admin membership, and the default General Space.
pub async fn create_company(
    db: &D1Database,
    company_id: &str,
    user_id: &str,
    name: &str,
    space_id: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare("INSERT INTO companies (id, name, created_at) VALUES (?1, ?2, ?3)")
        .bind(&[text(company_id), text(name), num(now_ms)])?
        .run()
        .await?;
    db.prepare(
        "INSERT INTO memberships (company_id, user_id, role, created_at)
         VALUES (?1, ?2, 'admin', ?3)",
    )
    .bind(&[text(company_id), text(user_id), num(now_ms)])?
    .run()
    .await?;
    insert_space(db, space_id, company_id, "General", "general", "", now_ms).await?;
    Ok(())
}

/// Inserts a Space.
pub async fn insert_space(
    db: &D1Database,
    id: &str,
    company_id: &str,
    name: &str,
    slug: &str,
    description: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO spaces
         (id, company_id, name, slug, description, created_at, archived_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
    )
    .bind(&[
        text(id),
        text(company_id),
        text(name),
        text(slug),
        text(description),
        num(now_ms),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Lists active Spaces for a company.
pub async fn list_spaces(db: &D1Database, company_id: &str) -> Result<Vec<SpaceRow>> {
    let fetched = db
        .prepare(
            "SELECT id, company_id, name, slug, description, archived_at
             FROM spaces
             WHERE company_id = ?1 AND archived_at IS NULL
             ORDER BY name",
        )
        .bind(&[text(company_id)])?
        .all()
        .await?;
    fetched.results()
}

/// Loads one Space in a company.
pub async fn get_space(
    db: &D1Database,
    company_id: &str,
    space_id: &str,
) -> Result<Option<SpaceRow>> {
    db.prepare(
        "SELECT id, company_id, name, slug, description, archived_at
         FROM spaces
         WHERE company_id = ?1 AND id = ?2",
    )
    .bind(&[text(company_id), text(space_id)])?
    .first(None)
    .await
}

/// Renames a Space.
pub async fn rename_space(
    db: &D1Database,
    company_id: &str,
    space_id: &str,
    name: &str,
) -> Result<()> {
    db.prepare("UPDATE spaces SET name = ?1 WHERE company_id = ?2 AND id = ?3")
        .bind(&[text(name), text(company_id), text(space_id)])?
        .run()
        .await?;
    Ok(())
}

/// Archives a Space. Pages stay; the Space leaves the default list.
pub async fn archive_space(
    db: &D1Database,
    company_id: &str,
    space_id: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "UPDATE spaces SET archived_at = ?1
         WHERE company_id = ?2 AND id = ?3 AND archived_at IS NULL",
    )
    .bind(&[num(now_ms), text(company_id), text(space_id)])?
    .run()
    .await?;
    Ok(())
}

/// Restores an archived Space.
pub async fn restore_space(db: &D1Database, company_id: &str, space_id: &str) -> Result<()> {
    db.prepare(
        "UPDATE spaces SET archived_at = NULL
         WHERE company_id = ?1 AND id = ?2 AND archived_at IS NOT NULL",
    )
    .bind(&[text(company_id), text(space_id)])?
    .run()
    .await?;
    Ok(())
}

/// Lists companies the user belongs to.
pub async fn list_memberships(db: &D1Database, user_id: &str) -> Result<Vec<MembershipRow>> {
    let fetched = db
        .prepare(
            "SELECT m.company_id AS company_id, c.name AS company_name, m.role AS role
             FROM memberships m
             JOIN companies c ON c.id = m.company_id
             WHERE m.user_id = ?1
             ORDER BY c.name",
        )
        .bind(&[text(user_id)])?
        .all()
        .await?;
    fetched.results()
}

/// Loads one membership.
pub async fn find_membership(
    db: &D1Database,
    company_id: &str,
    user_id: &str,
) -> Result<Option<Role>> {
    let row = db
        .prepare("SELECT role FROM memberships WHERE company_id = ?1 AND user_id = ?2")
        .bind(&[text(company_id), text(user_id)])?
        .first::<RoleRow>(None)
        .await?;
    Ok(row.and_then(|row| match row.role.as_str() {
        "admin" => Some(Role::Admin),
        "member" => Some(Role::Member),
        _ => None,
    }))
}

/// Changes a company name.
pub async fn rename_company(db: &D1Database, company_id: &str, name: &str) -> Result<()> {
    db.prepare("UPDATE companies SET name = ?1 WHERE id = ?2")
        .bind(&[text(name), text(company_id)])?
        .run()
        .await?;
    Ok(())
}

/// Adds a member. Fails at the database if the pair already exists.
pub async fn insert_membership(
    db: &D1Database,
    company_id: &str,
    user_id: &str,
    role: Role,
    now_ms: i64,
) -> Result<()> {
    let role = match role {
        Role::Admin => "admin",
        Role::Member => "member",
    };
    db.prepare(
        "INSERT INTO memberships (company_id, user_id, role, created_at)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&[text(company_id), text(user_id), text(role), num(now_ms)])?
    .run()
    .await?;
    Ok(())
}

/// Inserts a Page. The FTS trigger indexes it.
#[allow(clippy::too_many_arguments)]
pub async fn insert_article(
    db: &D1Database,
    id: &str,
    company_id: &str,
    space_id: &str,
    parent_id: Option<&str>,
    position: &str,
    title: &str,
    body: &str,
    author_id: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "INSERT INTO articles
         (id, company_id, space_id, parent_id, position, title, body, author_id,
          created_at, updated_at, deleted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, NULL)",
    )
    .bind(&[
        text(id),
        text(company_id),
        text(space_id),
        match parent_id {
            Some(value) => text(value),
            None => JsValue::NULL,
        },
        text(position),
        text(title),
        text(body),
        text(author_id),
        num(now_ms),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Replaces a Page's title and body.
pub async fn update_article(
    db: &D1Database,
    id: &str,
    company_id: &str,
    title: &str,
    body: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "UPDATE articles SET title = ?1, body = ?2, updated_at = ?3
         WHERE id = ?4 AND company_id = ?5 AND deleted_at IS NULL",
    )
    .bind(&[
        text(title),
        text(body),
        num(now_ms),
        text(id),
        text(company_id),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Moves a Page under a new parent and/or sibling order.
pub async fn move_article(
    db: &D1Database,
    id: &str,
    company_id: &str,
    parent_id: Option<&str>,
    position: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "UPDATE articles SET parent_id = ?1, position = ?2, updated_at = ?3
         WHERE id = ?4 AND company_id = ?5 AND deleted_at IS NULL",
    )
    .bind(&[
        match parent_id {
            Some(value) => text(value),
            None => JsValue::NULL,
        },
        text(position),
        num(now_ms),
        text(id),
        text(company_id),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Soft-deletes a Page. Attachment rows stay until hard cleanup.
pub async fn delete_article(
    db: &D1Database,
    id: &str,
    company_id: &str,
    now_ms: i64,
) -> Result<()> {
    db.prepare(
        "UPDATE articles SET deleted_at = ?1, updated_at = ?1
         WHERE id = ?2 AND company_id = ?3 AND deleted_at IS NULL",
    )
    .bind(&[num(now_ms), text(id), text(company_id)])?
    .run()
    .await?;
    Ok(())
}

/// Loads one Page in a company.
pub async fn get_article(
    db: &D1Database,
    company_id: &str,
    article_id: &str,
) -> Result<Option<ArticleRow>> {
    db.prepare(
        "SELECT id, space_id, parent_id, position, icon, title, body, author_id, updated_at
         FROM articles
         WHERE company_id = ?1 AND id = ?2 AND deleted_at IS NULL",
    )
    .bind(&[text(company_id), text(article_id)])?
    .first(None)
    .await
}

/// Lists Pages in a company, optionally by Space and FTS5 MATCH.
pub async fn list_articles(
    db: &D1Database,
    company_id: &str,
    space_id: Option<&str>,
    fts: Option<&str>,
) -> Result<Vec<ArticleRow>> {
    let fetched = match (space_id, fts) {
        (Some(space_id), Some(match_query)) => {
            db.prepare(
                "SELECT a.id, a.space_id, a.parent_id, a.position, a.icon, a.title, a.body,
                        a.author_id, a.updated_at
                 FROM articles a
                 JOIN articles_fts ON articles_fts.rowid = a.rowid
                 WHERE a.company_id = ?1 AND a.space_id = ?2 AND a.deleted_at IS NULL
                   AND articles_fts MATCH ?3
                 ORDER BY a.position, a.updated_at DESC
                 LIMIT 200",
            )
            .bind(&[text(company_id), text(space_id), text(match_query)])?
            .all()
            .await?
        }
        (Some(space_id), None) => {
            db.prepare(
                "SELECT id, space_id, parent_id, position, icon, title, body, author_id, updated_at
                 FROM articles
                 WHERE company_id = ?1 AND space_id = ?2 AND deleted_at IS NULL
                 ORDER BY position, updated_at DESC
                 LIMIT 200",
            )
            .bind(&[text(company_id), text(space_id)])?
            .all()
            .await?
        }
        (None, Some(match_query)) => {
            db.prepare(
                "SELECT a.id, a.space_id, a.parent_id, a.position, a.icon, a.title, a.body,
                        a.author_id, a.updated_at
                 FROM articles a
                 JOIN articles_fts ON articles_fts.rowid = a.rowid
                 WHERE a.company_id = ?1 AND a.deleted_at IS NULL AND articles_fts MATCH ?2
                 ORDER BY a.updated_at DESC
                 LIMIT 50",
            )
            .bind(&[text(company_id), text(match_query)])?
            .all()
            .await?
        }
        (None, None) => {
            db.prepare(
                "SELECT id, space_id, parent_id, position, icon, title, body, author_id, updated_at
                 FROM articles
                 WHERE company_id = ?1 AND deleted_at IS NULL
                 ORDER BY updated_at DESC
                 LIMIT 50",
            )
            .bind(&[text(company_id)])?
            .all()
            .await?
        }
    };
    fetched.results()
}

/// Columns written when an object has already been stored in R2.
pub struct NewAttachment<'a> {
    /// Attachment id.
    pub id: &'a str,
    /// Company that owns the file.
    pub company_id: &'a str,
    /// Article the file is attached to.
    pub article_id: &'a str,
    /// R2 object key.
    pub object_key: &'a str,
    /// Original file name.
    pub file_name: &'a str,
    /// Stored content type.
    pub content_type: &'a str,
    /// Size in bytes.
    pub byte_size: i64,
    /// User who uploaded the file.
    pub created_by: &'a str,
    /// Upload time, unix milliseconds.
    pub now_ms: i64,
}

/// Records an attachment after the object is in R2.
pub async fn insert_attachment(db: &D1Database, row: &NewAttachment<'_>) -> Result<()> {
    db.prepare(
        "INSERT INTO attachments
         (id, company_id, article_id, object_key, file_name, content_type,
          byte_size, created_by, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&[
        text(row.id),
        text(row.company_id),
        text(row.article_id),
        text(row.object_key),
        text(row.file_name),
        text(row.content_type),
        num(row.byte_size),
        text(row.created_by),
        num(row.now_ms),
    ])?
    .run()
    .await?;
    Ok(())
}

/// One file shown next to an article.
#[derive(Debug, Deserialize)]
pub struct AttachmentListRow {
    /// Attachment id.
    pub id: String,
    /// Original file name.
    pub file_name: String,
    /// Stored content type.
    pub content_type: String,
    /// Size in bytes.
    pub byte_size: i64,
}

/// Lists files for an article the caller is already allowed to read.
pub async fn list_attachments(
    db: &D1Database,
    company_id: &str,
    article_id: &str,
) -> Result<Vec<AttachmentListRow>> {
    let fetched = db
        .prepare(
            "SELECT id, file_name, content_type, byte_size FROM attachments
             WHERE company_id = ?1 AND article_id = ?2
             ORDER BY created_at",
        )
        .bind(&[text(company_id), text(article_id)])?
        .all()
        .await?;
    fetched.results()
}

/// Loads attachment metadata.
pub async fn get_attachment(
    db: &D1Database,
    company_id: &str,
    id: &str,
) -> Result<Option<AttachmentRow>> {
    db.prepare(
        "SELECT object_key, file_name, content_type
         FROM attachments WHERE company_id = ?1 AND id = ?2",
    )
    .bind(&[text(company_id), text(id)])?
    .first(None)
    .await
}

/// Lists object keys for hard cleanup of a soft-deleted page.
#[allow(dead_code)]
pub async fn list_attachment_keys(db: &D1Database, article_id: &str) -> Result<Vec<String>> {
    let fetched = db
        .prepare("SELECT object_key AS credential_id FROM attachments WHERE article_id = ?1")
        .bind(&[text(article_id)])?
        .all()
        .await?;
    let rows: Vec<IdNameRow> = fetched.results()?;
    Ok(rows.into_iter().map(|row| row.credential_id).collect())
}

/// Deletes attachment rows during hard cleanup of a soft-deleted page.
#[allow(dead_code)]
pub async fn delete_attachments(db: &D1Database, article_id: &str) -> Result<()> {
    db.prepare("DELETE FROM attachments WHERE article_id = ?1")
        .bind(&[text(article_id)])?
        .run()
        .await?;
    Ok(())
}

/// Deletes expired challenges and sessions. Safe to run more than once.
pub async fn cleanup(db: &D1Database, now_ms: i64) -> Result<()> {
    db.prepare("DELETE FROM email_challenges WHERE expires_at < ?1")
        .bind(&[num(now_ms)])?
        .run()
        .await?;
    db.prepare("DELETE FROM webauthn_challenges WHERE expires_at < ?1")
        .bind(&[num(now_ms)])?
        .run()
        .await?;
    db.prepare("DELETE FROM sessions WHERE expires_at < ?1 OR revoked_at IS NOT NULL")
        .bind(&[num(now_ms)])?
        .run()
        .await?;
    Ok(())
}

#[derive(Deserialize)]
struct CountRow {
    count: i64,
}

#[derive(Deserialize)]
struct EmailRow {
    email: String,
}

#[derive(Deserialize)]
struct IdRow {
    id: String,
}

#[derive(Deserialize)]
struct RoleRow {
    role: String,
}

#[derive(Deserialize)]
struct IdNameRow {
    credential_id: String,
}
