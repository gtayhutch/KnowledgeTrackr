//! Reads Worker variables. This is the only module that touches `env.var`.

use worker::{Env, Error, Result};

/// Runtime settings. Secrets are not included; this service has none.
#[derive(Clone)]
pub struct AppConfig {
    /// Browser origin allowed to call the API and to complete a passkey.
    pub app_origin: String,
    /// WebAuthn relying party id.
    pub rp_id: String,
    /// Name shown by the browser in the passkey prompt.
    pub rp_name: String,
    /// From address for enrollment and recovery mail.
    pub mail_from: String,
    /// When true, the session cookie carries `Secure`.
    pub cookie_secure: bool,
}

impl AppConfig {
    /// Loads the non-secret variables from the Worker environment.
    pub fn from_env(env: &Env) -> Result<Self> {
        Ok(Self {
            app_origin: required(env, "APP_ORIGIN")?,
            rp_id: required(env, "RP_ID")?,
            rp_name: required(env, "RP_NAME")?,
            mail_from: required(env, "MAIL_FROM")?,
            cookie_secure: required(env, "COOKIE_SECURE")?.eq_ignore_ascii_case("true"),
        })
    }
}

fn required(env: &Env, name: &str) -> Result<String> {
    env.var(name)
        .map(|value| value.to_string())
        .map_err(|_| Error::RustError(format!("missing variable {name}")))
}
