//! HTTP entry points.
//!
//! Each route parses the body, authenticates the session or email token,
//! authorizes the company action, then writes. A session cookie is set only
//! after a passkey ceremony succeeds. An email link never creates a session
//! by itself.

use serde_json::{json, Value};
use worker::*;

use crate::authz::{authorize, Action, Actor, Denial, Membership};
use crate::config::AppConfig;
use crate::limits::{
    CHALLENGE_TTL_MS, EMAIL_CHALLENGES_PER_HOUR, SESSION_TTL_MS, WEBAUTHN_CHALLENGES_PER_HOUR,
};
use crate::search_query::fts_match;
use crate::store::{self, PasskeyRow};
use crate::validate::{
    decode_b64, require_description, require_display_name, require_email, require_label,
    require_page_content, require_position, require_slug, require_upload, slug_from_name,
    ArticleMove, ArticleWrite, CeremonyBody, CompanyName, EmailLink, EmailStart, NewCompany,
    NewMember, SpaceWrite,
};
use crate::webauthn::{
    challenge_expiry, new_challenge, verify_authentication, verify_registration, CeremonyResponse,
    ExpectedCeremony, StoredPasskey,
};
use crate::{random_token, token_hash};

macro_rules! read_body {
    ($req:expr) => {
        match $req.json().await {
            Ok(value) => value,
            Err(_) => {
                return fail(
                    400,
                    "INVALID",
                    "Check the form and try again.",
                    Some("body"),
                )
            }
        }
    };
}

macro_rules! form {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => return fail(400, "INVALID", error.message, Some(error.field)),
        }
    };
}

/// Allowed caller, or a response that already explains the refusal.
enum Access {
    Allow(String),
    Deny(Response),
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let config = AppConfig::from_env(&env)?;
    if req.method() == Method::Options {
        return preflight(&config);
    }
    let response = Router::with_data(config.clone())
        .get_async("/api/health", health)
        .post_async("/api/auth/enroll/start", enroll_start)
        .post_async("/api/auth/enroll/options", enroll_options)
        .post_async("/api/auth/enroll/finish", enroll_finish)
        .post_async("/api/auth/recover/start", recover_start)
        .post_async("/api/auth/recover/options", recover_options)
        .post_async("/api/auth/recover/finish", recover_finish)
        .post_async("/api/auth/sign-in/options", sign_in_options)
        .post_async("/api/auth/sign-in/finish", sign_in_finish)
        .post_async("/api/auth/sign-out", sign_out)
        .get_async("/api/session", current_session)
        .get_async("/api/companies", current_session)
        .post_async("/api/companies", create_company)
        .patch_async("/api/companies/:company_id", rename_company)
        .post_async("/api/companies/:company_id/members", add_member)
        .get_async(
            "/api/companies/:company_id/mention-targets",
            mention_targets,
        )
        .get_async("/api/companies/:company_id/spaces", list_spaces)
        .post_async("/api/companies/:company_id/spaces", create_space)
        .patch_async("/api/companies/:company_id/spaces/:space_id", rename_space)
        .post_async(
            "/api/companies/:company_id/spaces/:space_id/archive",
            archive_space,
        )
        .post_async(
            "/api/companies/:company_id/spaces/:space_id/restore",
            restore_space,
        )
        .get_async("/api/companies/:company_id/articles", list_articles)
        .post_async("/api/companies/:company_id/articles", create_article)
        .get_async(
            "/api/companies/:company_id/articles/:article_id",
            read_article,
        )
        .put_async(
            "/api/companies/:company_id/articles/:article_id",
            update_article,
        )
        .post_async(
            "/api/companies/:company_id/articles/:article_id/move",
            move_article,
        )
        .delete_async(
            "/api/companies/:company_id/articles/:article_id",
            delete_article,
        )
        .get_async(
            "/api/companies/:company_id/articles/:article_id/attachments",
            list_attachments,
        )
        .post_async(
            "/api/companies/:company_id/articles/:article_id/attachments",
            upload_attachment,
        )
        .get_async(
            "/api/companies/:company_id/attachments/:attachment_id",
            download_attachment,
        )
        .run(req, env)
        .await?;
    Ok(with_security(response, &config))
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let now_ms = Date::now().as_millis() as i64;
    match env.d1("DB") {
        Ok(db) => match store::cleanup(&db, now_ms).await {
            Ok(()) => console_log!("{}", json!({"event": "cleanup_finished"})),
            Err(error) => console_log!(
                "{}",
                json!({"event": "cleanup_failed", "error": error.to_string()})
            ),
        },
        Err(error) => console_log!(
            "{}",
            json!({"event": "cleanup_failed", "error": error.to_string()})
        ),
    }
}

async fn health(_req: Request, _ctx: RouteContext<AppConfig>) -> Result<Response> {
    Response::from_json(&json!({"ok": true, "data": {"service": "knowledgetrackr"}}))
}

async fn enroll_start(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: EmailStart = read_body!(req);
    let email = form!(require_email(&body.email));
    // The name is checked here so a half-filled form does not send mail.
    // The finish call stores the name the person confirms on the link page.
    form!(require_display_name(
        body.display_name.as_deref().unwrap_or("")
    ));
    let db = ctx.env.d1("DB")?;
    let now_ms = now_ms();
    if email_limited(&db, &email, now_ms).await? {
        return fail(429, "RATE_LIMITED", "Wait a while, then try again.", None);
    }
    if store::find_user_by_email(&db, &email).await?.is_some() {
        return fail(
            409,
            "CONFLICT",
            "That email already has an account.",
            Some("email"),
        );
    }
    let token = random_token();
    store::insert_email_challenge(
        &db,
        &random_token(),
        &email,
        "enroll",
        &token_hash(&token),
        now_ms,
        now_ms + CHALLENGE_TTL_MS,
    )
    .await?;
    send_link(
        &ctx,
        &email,
        "Create your KnowledgeTrackr passkey",
        &format!(
            "Open this link on this device and create a passkey. The link expires in 15 minutes.\n\n{}/#/enroll/{token}",
            ctx.data.app_origin
        ),
    )
    .await?;
    console_log!("{}", json!({"event": "enroll_link_sent"}));
    Response::from_json(&json!({"ok": true}))
}

async fn enroll_options(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: EmailLink = read_body!(req);
    let display_name = form!(require_display_name(
        body.display_name.as_deref().unwrap_or("")
    ));
    creation_options(&ctx, &body.token, "enroll", Some(display_name)).await
}

async fn enroll_finish(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: CeremonyBody = read_body!(req);
    finish_registration(body, &ctx, "enroll").await
}

async fn recover_start(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: EmailStart = read_body!(req);
    let email = form!(require_email(&body.email));
    let db = ctx.env.d1("DB")?;
    let now_ms = now_ms();
    if email_limited(&db, &email, now_ms).await? {
        return fail(429, "RATE_LIMITED", "Wait a while, then try again.", None);
    }
    if store::find_user_by_email(&db, &email).await?.is_none() {
        console_log!("{}", json!({"event": "recover_unknown_email"}));
        return Response::from_json(&json!({"ok": true}));
    }
    let token = random_token();
    store::insert_email_challenge(
        &db,
        &random_token(),
        &email,
        "recover",
        &token_hash(&token),
        now_ms,
        now_ms + CHALLENGE_TTL_MS,
    )
    .await?;
    send_link(
        &ctx,
        &email,
        "Replace your KnowledgeTrackr passkey",
        &format!(
            "Open this link and create a new passkey. The link expires in 15 minutes.\n\n{}/#/recover/{token}",
            ctx.data.app_origin
        ),
    )
    .await?;
    console_log!("{}", json!({"event": "recover_link_sent"}));
    Response::from_json(&json!({"ok": true}))
}

async fn recover_options(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: EmailLink = read_body!(req);
    creation_options(&ctx, &body.token, "recover", None).await
}

async fn recover_finish(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: CeremonyBody = read_body!(req);
    finish_registration(body, &ctx, "recover").await
}

async fn sign_in_options(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: EmailStart = read_body!(req);
    let email = form!(require_email(&body.email));
    let db = ctx.env.d1("DB")?;
    let Some(user) = store::find_user_by_email(&db, &email).await? else {
        return fail(401, "UNAUTHORIZED", "Sign-in failed.", None);
    };
    let ids = store::list_credential_ids(&db, &user.id).await?;
    if ids.is_empty() {
        return fail(401, "UNAUTHORIZED", "Sign-in failed.", None);
    }
    let now_ms = now_ms();
    if webauthn_limited(&db, &email, now_ms).await? {
        return fail(429, "RATE_LIMITED", "Wait a while, then try again.", None);
    }
    let challenge = new_challenge();
    store::insert_webauthn_challenge(
        &db,
        &random_token(),
        &email,
        "authenticate",
        &challenge,
        now_ms,
        challenge_expiry(now_ms),
    )
    .await?;
    let allow: Vec<Value> = ids
        .iter()
        .map(|id| json!({"type": "public-key", "id": id}))
        .collect();
    Response::from_json(&json!({
        "ok": true,
        "data": {
            "challenge": challenge,
            "rpId": ctx.data.rp_id,
            "allowCredentials": allow,
            "userVerification": "required",
            "timeout": 60000
        }
    }))
}

async fn sign_in_finish(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: CeremonyBody = read_body!(req);
    let email = match body.email.as_deref().map(require_email) {
        Some(Ok(email)) => email,
        Some(Err(error)) => return fail(400, "INVALID", error.message, Some(error.field)),
        None => return fail(400, "INVALID", "Enter an email address.", Some("email")),
    };
    let client_data_json = form!(decode_b64("clientDataJSON", &body.client_data_json));
    let authenticator_data = form!(decode_b64("authenticatorData", &body.authenticator_data));
    let signature = form!(decode_b64(
        "signature",
        body.signature.as_deref().unwrap_or("")
    ));
    let Some(challenge) = json_string(&client_data_json, "challenge") else {
        return fail(
            400,
            "INVALID",
            "The passkey response was incomplete.",
            Some("body"),
        );
    };
    let db = ctx.env.d1("DB")?;
    let now_ms = now_ms();
    let Some(user) = store::find_user_by_email(&db, &email).await? else {
        return fail(401, "UNAUTHORIZED", "Sign-in failed.", None);
    };
    let Some(passkey) = store::find_passkey(&db, &user.id, &body.credential_id).await? else {
        return fail(401, "UNAUTHORIZED", "Sign-in failed.", None);
    };
    if !store::consume_webauthn_challenge(&db, &email, "authenticate", &challenge, now_ms).await? {
        return fail(401, "UNAUTHORIZED", "Sign-in failed.", None);
    }
    let counter = match verify_authentication(
        &ExpectedCeremony {
            ceremony_type: "webauthn.get",
            challenge,
            origin: ctx.data.app_origin.clone(),
            rp_id: ctx.data.rp_id.clone(),
        },
        &CeremonyResponse {
            client_data_json,
            authenticator_data,
            signature,
            public_key_spki: None,
        },
        &stored(&passkey),
    ) {
        Ok(counter) => counter,
        Err(_) => return fail(401, "UNAUTHORIZED", "Sign-in failed.", None),
    };
    store::set_counter(&db, &passkey.credential_id, counter).await?;
    issue_session(&ctx, &db, &user.id, now_ms).await
}

async fn sign_out(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    if let Some(session_id) = cookie_session(&req) {
        let db = ctx.env.d1("DB")?;
        store::revoke_session(&db, &session_id, now_ms()).await?;
        console_log!("{}", json!({"event": "sign_out"}));
    }
    let mut response = Response::from_json(&json!({"ok": true}))?;
    set_cookie(&mut response, &ctx.data, None)?;
    Ok(response)
}

async fn current_session(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let db = ctx.env.d1("DB")?;
    let Some((user_id, _)) = live_user(&req, &db).await? else {
        return fail(401, "UNAUTHORIZED", "Sign in again.", None);
    };
    let Some(user) = store::find_user(&db, &user_id).await? else {
        return fail(401, "UNAUTHORIZED", "Sign in again.", None);
    };
    let companies = store::list_memberships(&db, &user_id).await?;
    let listed: Vec<Value> = companies
        .iter()
        .map(|row| {
            json!({
                "id": row.company_id,
                "name": row.company_name,
                "role": row.role
            })
        })
        .collect();
    Response::from_json(&json!({
        "ok": true,
        "data": {
            "user": {"id": user.id, "email": user.email, "displayName": user.display_name},
            "companies": listed
        }
    }))
}

async fn create_company(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let body: NewCompany = read_body!(req);
    let name = form!(require_label("name", &body.name, 80));
    let db = ctx.env.d1("DB")?;
    let Some((user_id, _)) = live_user(&req, &db).await? else {
        return fail(401, "UNAUTHORIZED", "Sign in again.", None);
    };
    let company_id = random_token();
    let space_id = random_token();
    store::create_company(&db, &company_id, &user_id, &name, &space_id, now_ms()).await?;
    console_log!("{}", json!({"event": "company_created", "userId": user_id}));
    Response::from_json(&json!({
        "ok": true,
        "data": {
            "id": company_id,
            "name": name,
            "defaultSpaceId": space_id
        }
    }))
}

async fn list_spaces(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ReadArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let rows = store::list_spaces(&db, &company_id).await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "name": row.name,
                "slug": row.slug,
                "description": row.description
            })
        })
        .collect();
    Response::from_json(&json!({"ok": true, "data": data}))
}

async fn create_space(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let body: SpaceWrite = read_body!(req);
    let name = form!(require_label("name", &body.name, 80));
    let description = form!(require_description(
        body.description.as_deref().unwrap_or("")
    ));
    let slug = match body.slug.as_deref() {
        Some(value) => form!(require_slug("slug", value)),
        None => form!(require_slug("slug", &slug_from_name(&name))),
    };
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let id = random_token();
    if store::insert_space(&db, &id, &company_id, &name, &slug, &description, now_ms())
        .await
        .is_err()
    {
        return fail(
            409,
            "CONFLICT",
            "A space with that slug already exists.",
            Some("slug"),
        );
    }
    Response::from_json(&json!({"ok": true, "data": {"id": id, "slug": slug}}))
}

async fn rename_space(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let space_id = param(&ctx, "space_id")?;
    let body: SpaceWrite = read_body!(req);
    let name = form!(require_label("name", &body.name, 80));
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if store::get_space(&db, &company_id, &space_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That space is not available.", None);
    }
    store::rename_space(&db, &company_id, &space_id, &name).await?;
    Response::from_json(&json!({"ok": true}))
}

async fn archive_space(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let space_id = param(&ctx, "space_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if store::get_space(&db, &company_id, &space_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That space is not available.", None);
    }
    store::archive_space(&db, &company_id, &space_id, now_ms()).await?;
    Response::from_json(&json!({"ok": true}))
}

async fn restore_space(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let space_id = param(&ctx, "space_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if store::get_space(&db, &company_id, &space_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That space is not available.", None);
    }
    store::restore_space(&db, &company_id, &space_id).await?;
    Response::from_json(&json!({"ok": true}))
}

async fn rename_company(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let body: CompanyName = read_body!(req);
    let name = form!(require_label("name", &body.name, 80));
    let db = ctx.env.d1("DB")?;
    let user_id = match access(&req, &db, &company_id, Action::UpdateCompany).await? {
        Access::Allow(user_id) => user_id,
        Access::Deny(response) => return Ok(response),
    };
    store::rename_company(&db, &company_id, &name).await?;
    console_log!("{}", json!({"event": "company_renamed", "userId": user_id}));
    Response::from_json(&json!({"ok": true}))
}

async fn add_member(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let body: NewMember = read_body!(req);
    let email = form!(require_email(&body.email));
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ManageMembers).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let Some(user) = store::find_user_by_email(&db, &email).await? else {
        return fail(
            404,
            "NOT_FOUND",
            "That person does not have an account yet.",
            Some("email"),
        );
    };
    if store::insert_membership(&db, &company_id, &user.id, body.role, now_ms())
        .await
        .is_err()
    {
        return fail(
            409,
            "CONFLICT",
            "That person is already a member.",
            Some("email"),
        );
    }
    console_log!(
        "{}",
        json!({"event": "member_added", "companyId": company_id})
    );
    Response::from_json(&json!({"ok": true}))
}

async fn list_articles(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let url = req.url()?;
    let mut query = String::new();
    let mut space_id: Option<String> = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "q" => query = value.into_owned(),
            "spaceId" => space_id = Some(value.into_owned()),
            _ => {}
        }
    }
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ReadArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if let Some(ref space_id) = space_id {
        if store::get_space(&db, &company_id, space_id)
            .await?
            .is_none()
        {
            return fail(404, "NOT_FOUND", "That space is not available.", None);
        }
    }
    let rows = store::list_articles(
        &db,
        &company_id,
        space_id.as_deref(),
        fts_match(&query).as_deref(),
    )
    .await?;
    let data: Vec<Value> = rows.iter().map(page_summary_json).collect();
    Response::from_json(&json!({"ok": true, "data": data}))
}

async fn mention_targets(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let url = req.url()?;
    let space_id = url
        .query_pairs()
        .find(|(key, _)| key == "spaceId")
        .map(|(_, value)| value.into_owned());
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ReadArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let members = store::list_company_members(&db, &company_id).await?;
    let pages = store::list_articles(&db, &company_id, space_id.as_deref(), None).await?;
    let people: Vec<Value> = members
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "label": row.display_name,
                "email": row.email,
                "kind": "person"
            })
        })
        .collect();
    let page_targets: Vec<Value> = pages
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "label": row.title,
                "spaceId": row.space_id,
                "kind": "page"
            })
        })
        .collect();
    Response::from_json(&json!({
        "ok": true,
        "data": {
            "people": people,
            "pages": page_targets
        }
    }))
}

async fn create_article(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let body: ArticleWrite = read_body!(req);
    let (title, content_json, article_body) =
        form!(require_page_content(&body.title, &body.content));
    let Some(space_id) = body
        .space_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return fail(400, "INVALID", "Choose a space.", Some("spaceId"));
    };
    let parent_id = body
        .parent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let db = ctx.env.d1("DB")?;
    let user_id = match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(user_id) => user_id,
        Access::Deny(response) => return Ok(response),
    };
    if store::get_space(&db, &company_id, space_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That space is not available.", None);
    }
    if let Some(parent_id) = parent_id {
        let Some(parent) = store::get_article(&db, &company_id, parent_id).await? else {
            return fail(404, "NOT_FOUND", "That parent page is not available.", None);
        };
        if parent.space_id != space_id {
            return fail(
                400,
                "INVALID",
                "The parent page must be in the same space.",
                Some("parentId"),
            );
        }
    }
    let id = random_token();
    let now = now_ms();
    store::insert_article(
        &db,
        &id,
        &company_id,
        space_id,
        parent_id,
        &id,
        &title,
        &article_body,
        &content_json,
        &user_id,
        now,
    )
    .await?;
    Response::from_json(&json!({"ok": true, "data": {"id": id, "updatedAt": now}}))
}

async fn read_article(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let article_id = param(&ctx, "article_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ReadArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let Some(row) = store::get_article(&db, &company_id, &article_id).await? else {
        return fail(404, "NOT_FOUND", "That page is not available.", None);
    };
    Response::from_json(&json!({"ok": true, "data": page_json(&row)}))
}

async fn update_article(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let article_id = param(&ctx, "article_id")?;
    let body: ArticleWrite = read_body!(req);
    let (title, content_json, article_body) =
        form!(require_page_content(&body.title, &body.content));
    let Some(expected_updated_at) = body.expected_updated_at else {
        return fail(
            400,
            "INVALID",
            "Send the last saved time.",
            Some("expectedUpdatedAt"),
        );
    };
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if store::get_article(&db, &company_id, &article_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That page is not available.", None);
    }
    let now = now_ms();
    let updated = store::update_article(
        &db,
        &article_id,
        &company_id,
        &title,
        &article_body,
        &content_json,
        expected_updated_at,
        now,
    )
    .await?;
    if !updated {
        return fail(
            409,
            "CONFLICT",
            "Someone else saved this page. Reload before editing again.",
            None,
        );
    }
    Response::from_json(&json!({"ok": true, "data": {"updatedAt": now}}))
}

async fn move_article(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let article_id = param(&ctx, "article_id")?;
    let body: ArticleMove = read_body!(req);
    let position = form!(require_position(&body.position));
    let parent_id = body
        .parent_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let Some(page) = store::get_article(&db, &company_id, &article_id).await? else {
        return fail(404, "NOT_FOUND", "That page is not available.", None);
    };
    if parent_id == Some(article_id.as_str()) {
        return fail(
            400,
            "INVALID",
            "A page cannot be its own parent.",
            Some("parentId"),
        );
    }
    if let Some(parent_id) = parent_id {
        let Some(parent) = store::get_article(&db, &company_id, parent_id).await? else {
            return fail(404, "NOT_FOUND", "That parent page is not available.", None);
        };
        if parent.space_id != page.space_id {
            return fail(
                400,
                "INVALID",
                "The parent page must be in the same space.",
                Some("parentId"),
            );
        }
    }
    store::move_article(
        &db,
        &article_id,
        &company_id,
        parent_id,
        &position,
        now_ms(),
    )
    .await?;
    Response::from_json(&json!({"ok": true}))
}

async fn delete_article(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let article_id = param(&ctx, "article_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if store::get_article(&db, &company_id, &article_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That page is not available.", None);
    }
    store::delete_article(&db, &article_id, &company_id, now_ms()).await?;
    Response::from_json(&json!({"ok": true}))
}

async fn list_attachments(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let article_id = param(&ctx, "article_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ReadArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    if store::get_article(&db, &company_id, &article_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That page is not available.", None);
    }
    let rows = store::list_attachments(&db, &company_id, &article_id).await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "fileName": row.file_name,
                "contentType": row.content_type,
                "byteSize": row.byte_size
            })
        })
        .collect();
    Response::from_json(&json!({"ok": true, "data": data}))
}

async fn upload_attachment(mut req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let article_id = param(&ctx, "article_id")?;
    let file_name = req.headers().get("x-file-name")?.unwrap_or_default();
    let content_type = req.headers().get("content-type")?.unwrap_or_default();
    let content_type = content_type.split(';').next().unwrap_or("").trim();
    let bytes = req.bytes().await?;
    let byte_size = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    let file_name = form!(require_upload(&file_name, content_type, bytes.len()));
    let db = ctx.env.d1("DB")?;
    let user_id = match access(&req, &db, &company_id, Action::WriteArticle).await? {
        Access::Allow(user_id) => user_id,
        Access::Deny(response) => return Ok(response),
    };
    if store::get_article(&db, &company_id, &article_id)
        .await?
        .is_none()
    {
        return fail(404, "NOT_FOUND", "That page is not available.", None);
    }
    let id = random_token();
    let object_key = format!("companies/{company_id}/articles/{article_id}/{id}");
    let files = ctx.env.bucket("FILES")?;
    files.put(&object_key, bytes).execute().await?;
    if let Err(error) = store::insert_attachment(
        &db,
        &store::NewAttachment {
            id: &id,
            company_id: &company_id,
            article_id: &article_id,
            object_key: &object_key,
            file_name: &file_name,
            content_type,
            byte_size,
            created_by: &user_id,
            now_ms: now_ms(),
        },
    )
    .await
    {
        let _ = files.delete(&object_key).await;
        return Err(error);
    }
    Response::from_json(&json!({"ok": true, "data": {"id": id, "fileName": file_name}}))
}

async fn download_attachment(req: Request, ctx: RouteContext<AppConfig>) -> Result<Response> {
    let company_id = param(&ctx, "company_id")?;
    let attachment_id = param(&ctx, "attachment_id")?;
    let db = ctx.env.d1("DB")?;
    match access(&req, &db, &company_id, Action::ReadArticle).await? {
        Access::Allow(_) => {}
        Access::Deny(response) => return Ok(response),
    }
    let Some(row) = store::get_attachment(&db, &company_id, &attachment_id).await? else {
        return fail(404, "NOT_FOUND", "That file is not available.", None);
    };
    let files = ctx.env.bucket("FILES")?;
    let Some(object) = files.get(&row.object_key).execute().await? else {
        return fail(404, "NOT_FOUND", "That file is not available.", None);
    };
    let body = object
        .body()
        .ok_or_else(|| Error::RustError("empty object".into()))?;
    let mut response = Response::from_body(body.response_body()?)?;
    response
        .headers_mut()
        .set("content-type", &row.content_type)?;
    response.headers_mut().set(
        "content-disposition",
        &format!("attachment; filename=\"{}\"", row.file_name),
    )?;
    Ok(response)
}

/// Issues a creation challenge after the email token checks out.
async fn creation_options(
    ctx: &RouteContext<AppConfig>,
    token: &str,
    purpose: &str,
    display_name: Option<String>,
) -> Result<Response> {
    let db = ctx.env.d1("DB")?;
    let now_ms = now_ms();
    let Some(email) = store::find_email_challenge(&db, purpose, &token_hash(token), now_ms).await?
    else {
        return fail(401, "UNAUTHORIZED", "That link is no longer valid.", None);
    };
    let user = store::find_user_by_email(&db, &email).await?;
    if purpose == "enroll" && user.is_some() {
        return fail(
            409,
            "CONFLICT",
            "That email already has an account.",
            Some("email"),
        );
    }
    if purpose == "recover" && user.is_none() {
        return fail(401, "UNAUTHORIZED", "That link is no longer valid.", None);
    }
    if webauthn_limited(&db, &email, now_ms).await? {
        return fail(429, "RATE_LIMITED", "Wait a while, then try again.", None);
    }
    let challenge = new_challenge();
    store::insert_webauthn_challenge(
        &db,
        &random_token(),
        &email,
        purpose,
        &challenge,
        now_ms,
        challenge_expiry(now_ms),
    )
    .await?;
    let name = match display_name {
        Some(name) => name,
        None => user
            .map(|row| row.display_name)
            .unwrap_or_else(|| email.clone()),
    };
    Response::from_json(&json!({
        "ok": true,
        "data": {
            "challenge": challenge,
            "rpId": ctx.data.rp_id,
            "rpName": ctx.data.rp_name,
            "userHandle": random_token(),
            "userName": email,
            "userDisplayName": name,
            "timeout": 60000
        }
    }))
}

async fn finish_registration(
    body: CeremonyBody,
    ctx: &RouteContext<AppConfig>,
    purpose: &str,
) -> Result<Response> {
    let Some(token) = body.token.as_deref() else {
        return fail(
            400,
            "INVALID",
            "Open the link from your email.",
            Some("token"),
        );
    };
    let client_data_json = form!(decode_b64("clientDataJSON", &body.client_data_json));
    let authenticator_data = form!(decode_b64("authenticatorData", &body.authenticator_data));
    let public_key = match body.public_key.as_deref() {
        Some(value) => form!(decode_b64("publicKey", value)),
        None => {
            return fail(
                400,
                "INVALID",
                "The passkey response was incomplete.",
                Some("publicKey"),
            )
        }
    };
    let Some(challenge) = json_string(&client_data_json, "challenge") else {
        return fail(
            400,
            "INVALID",
            "The passkey response was incomplete.",
            Some("body"),
        );
    };
    let db = ctx.env.d1("DB")?;
    let now_ms = now_ms();
    let Some(email) = store::find_email_challenge(&db, purpose, &token_hash(token), now_ms).await?
    else {
        return fail(401, "UNAUTHORIZED", "That link is no longer valid.", None);
    };
    let spki = match verify_registration(
        &ExpectedCeremony {
            ceremony_type: "webauthn.create",
            challenge: challenge.clone(),
            origin: ctx.data.app_origin.clone(),
            rp_id: ctx.data.rp_id.clone(),
        },
        &CeremonyResponse {
            client_data_json,
            authenticator_data,
            signature: Vec::new(),
            public_key_spki: Some(public_key),
        },
    ) {
        Ok(spki) => spki,
        Err(_) => {
            return fail(
                401,
                "UNAUTHORIZED",
                "The passkey could not be verified.",
                None,
            )
        }
    };
    if !store::consume_webauthn_challenge(&db, &email, purpose, &challenge, now_ms).await? {
        return fail(401, "UNAUTHORIZED", "That link is no longer valid.", None);
    }
    let user_id = if purpose == "recover" {
        let Some(user) = store::find_user_by_email(&db, &email).await? else {
            return fail(401, "UNAUTHORIZED", "That link is no longer valid.", None);
        };
        store::delete_passkeys(&db, &user.id).await?;
        user.id
    } else {
        let name = form!(require_display_name(
            body.display_name.as_deref().unwrap_or("")
        ));
        match store::find_user_by_email(&db, &email).await? {
            Some(user) => user.id,
            None => {
                let id = random_token();
                store::insert_user(&db, &id, &email, &name, now_ms).await?;
                id
            }
        }
    };
    store::insert_passkey(&db, &body.credential_id, &user_id, &spki, now_ms).await?;
    store::consume_email_challenge(&db, purpose, &token_hash(token), now_ms).await?;
    console_log!(
        "{}",
        json!({"event": "passkey_registered", "userId": user_id})
    );
    issue_session(ctx, &db, &user_id, now_ms).await
}

fn stored(row: &PasskeyRow) -> StoredPasskey {
    StoredPasskey {
        credential_id: row.credential_id.clone(),
        public_key_spki: row.public_key_spki.clone(),
        signature_counter: u32::try_from(row.signature_counter).unwrap_or(0),
    }
}

async fn issue_session(
    ctx: &RouteContext<AppConfig>,
    db: &D1Database,
    user_id: &str,
    now_ms: i64,
) -> Result<Response> {
    let session_id = random_token();
    store::insert_session(db, &session_id, user_id, now_ms, now_ms + SESSION_TTL_MS).await?;
    let mut response = Response::from_json(&json!({"ok": true}))?;
    set_cookie(&mut response, &ctx.data, Some(&session_id))?;
    console_log!("{}", json!({"event": "session_created", "userId": user_id}));
    Ok(response)
}

async fn live_user(req: &Request, db: &D1Database) -> Result<Option<(String, i64)>> {
    let Some(session_id) = cookie_session(req) else {
        return Ok(None);
    };
    let now_ms = now_ms();
    let Some(session) = store::find_live_session(db, &session_id, now_ms).await? else {
        return Ok(None);
    };
    Ok(Some((session.user_id, now_ms - session.created_at)))
}

async fn access(
    req: &Request,
    db: &D1Database,
    company_id: &str,
    action: Action,
) -> Result<Access> {
    let Some((user_id, age)) = live_user(req, db).await? else {
        return Ok(Access::Deny(fail(
            401,
            "UNAUTHORIZED",
            "Sign in again.",
            None,
        )?));
    };
    let role = store::find_membership(db, company_id, &user_id).await?;
    let membership = role.map(|role| Membership {
        company_id: company_id.to_string(),
        user_id: user_id.clone(),
        role,
    });
    let actor = Actor::User {
        user_id: user_id.clone(),
    };
    match authorize(&actor, company_id, membership.as_ref(), action, age) {
        Ok(()) => Ok(Access::Allow(user_id)),
        Err(denial) => Ok(Access::Deny(denial_response(denial)?)),
    }
}

fn denial_response(denial: Denial) -> Result<Response> {
    match denial {
        Denial::SignedOut => fail(401, "UNAUTHORIZED", "Sign in again.", None),
        Denial::NotAMember | Denial::NotAnAdmin => {
            fail(403, "FORBIDDEN", "You cannot do that.", None)
        }
        Denial::ReauthenticationRequired => fail(
            401,
            "REAUTH_REQUIRED",
            "Sign in again to change membership or the company name.",
            None,
        ),
    }
}

async fn email_limited(db: &D1Database, email: &str, now_ms: i64) -> Result<bool> {
    let recent = store::count_email_challenges(db, email, now_ms - 60 * 60 * 1000).await?;
    Ok(recent >= EMAIL_CHALLENGES_PER_HOUR)
}

async fn webauthn_limited(db: &D1Database, email: &str, now_ms: i64) -> Result<bool> {
    let recent = store::count_webauthn_challenges(db, email, now_ms - 60 * 60 * 1000).await?;
    Ok(recent >= WEBAUTHN_CHALLENGES_PER_HOUR)
}

fn page_summary_json(row: &store::ArticleRow) -> Value {
    json!({
        "id": row.id,
        "spaceId": row.space_id,
        "parentId": row.parent_id,
        "position": row.position,
        "icon": row.icon,
        "title": row.title,
        "authorId": row.author_id,
        "updatedAt": row.updated_at
    })
}

fn page_json(row: &store::ArticleRow) -> Value {
    let content = if row.content_json.trim().is_empty() {
        json!({
            "type": "doc",
            "content": [{
                "type": "paragraph",
                "content": if row.body.is_empty() {
                    vec![]
                } else {
                    vec![json!({"type": "text", "text": row.body})]
                }
            }]
        })
    } else {
        serde_json::from_str(&row.content_json).unwrap_or_else(|_| {
            json!({
                "type": "doc",
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": row.body}]
                }]
            })
        })
    };
    json!({
        "id": row.id,
        "spaceId": row.space_id,
        "parentId": row.parent_id,
        "position": row.position,
        "icon": row.icon,
        "title": row.title,
        "body": row.body,
        "content": content,
        "authorId": row.author_id,
        "updatedAt": row.updated_at
    })
}

fn fail(status: u16, code: &str, message: &str, field_name: Option<&str>) -> Result<Response> {
    let mut body = json!({"ok": false, "code": code, "message": message});
    if let Some(field_name) = field_name {
        body["field"] = json!(field_name);
    }
    Ok(Response::from_json(&body)?.with_status(status))
}

fn param(ctx: &RouteContext<AppConfig>, name: &str) -> Result<String> {
    ctx.param(name)
        .map(ToString::to_string)
        .ok_or_else(|| Error::RustError(format!("missing {name}")))
}

fn cookie_session(req: &Request) -> Option<String> {
    let header = req.headers().get("cookie").ok().flatten()?;
    header.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == "kt_session").then(|| value.to_string())
    })
}

fn set_cookie(response: &mut Response, config: &AppConfig, session_id: Option<&str>) -> Result<()> {
    let cookie = match session_id {
        Some(id) => {
            let mut value = format!(
                "kt_session={id}; HttpOnly; Path=/; SameSite=Lax; Max-Age={}",
                SESSION_TTL_MS / 1000
            );
            if config.cookie_secure {
                value.push_str("; Secure");
            }
            value
        }
        None => "kt_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0".to_string(),
    };
    response.headers_mut().set("set-cookie", &cookie)
}

fn with_security(mut response: Response, config: &AppConfig) -> Response {
    let headers = response.headers_mut();
    let _ = headers.set("access-control-allow-origin", &config.app_origin);
    let _ = headers.set("access-control-allow-credentials", "true");
    let _ = headers.set("vary", "Origin");
    let _ = headers.set("x-content-type-options", "nosniff");
    let _ = headers.set("referrer-policy", "no-referrer");
    let _ = headers.set("x-frame-options", "DENY");
    let _ = headers.set("cache-control", "no-store");
    response
}

fn preflight(config: &AppConfig) -> Result<Response> {
    let mut response = Response::empty()?;
    let headers = response.headers_mut();
    headers.set("access-control-allow-origin", &config.app_origin)?;
    headers.set("access-control-allow-credentials", "true")?;
    headers.set("access-control-allow-headers", "content-type, x-file-name")?;
    headers.set(
        "access-control-allow-methods",
        "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    )?;
    headers.set("access-control-max-age", "600")?;
    Ok(response)
}

async fn send_link(
    ctx: &RouteContext<AppConfig>,
    to: &str,
    subject: &str,
    text: &str,
) -> Result<()> {
    let sender = ctx.env.send_email("EMAIL")?;
    let from = email::EmailAddress::new("KnowledgeTrackr", &ctx.data.mail_from);
    let builder = email::SendEmailBuilder::builder_with_email_address_and_str(&from, to, subject)
        .text(text)
        .build();
    sender.send_with_builder(&builder).await?;
    Ok(())
}

fn json_string(bytes: &[u8], field_name: &str) -> Option<String> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    value.get(field_name)?.as_str().map(str::to_string)
}

fn now_ms() -> i64 {
    Date::now().as_millis() as i64
}
