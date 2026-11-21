//! Library root. HTTP entry points live in [`http`] and compile only for
//! the Workers target. Domain checks compile and run under `cargo test`.

use base64::Engine;

pub mod authz;
pub mod limits;
pub mod search_query;
pub mod validate;
pub mod webauthn;

#[cfg(target_arch = "wasm32")]
mod config;
#[cfg(target_arch = "wasm32")]
mod http;
#[cfg(target_arch = "wasm32")]
mod store;

/// Hashes an email token before it is stored.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(&Sha256::digest(token.as_bytes()))
}

/// Returns 32 random bytes encoded as base64url. Used for ids and tokens.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("random token");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
