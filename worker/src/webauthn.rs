//! Passkey checks for enrollment, sign-in, and recovery.
//!
//! An email token never creates a session. A session is created only after
//! this module accepts a passkey ceremony for the configured origin.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

use crate::limits::CHALLENGE_TTL_MS;

/// Why a passkey ceremony was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    /// The client data was not the JSON object WebAuthn sends.
    Malformed,
    /// The challenge, origin, or relying party id did not match.
    Mismatch,
    /// The authenticator did not assert user presence and verification.
    UserNotVerified,
    /// The signature or the stored public key was not usable.
    BadSignature,
    /// The signature counter went backwards.
    CounterRewound,
}

/// Values the Worker told the browser to use for one ceremony.
#[derive(Debug, Clone)]
pub struct ExpectedCeremony {
    /// `webauthn.create` or `webauthn.get`.
    pub ceremony_type: &'static str,
    /// Base64url challenge that was issued.
    pub challenge: String,
    /// Page origin, for example `http://localhost:5173`.
    pub origin: String,
    /// Relying party id, for example `localhost`.
    pub rp_id: String,
}

/// What the browser posts back after `navigator.credentials`.
#[derive(Debug, Clone)]
pub struct CeremonyResponse {
    /// `response.clientDataJSON`, already decoded.
    pub client_data_json: Vec<u8>,
    /// `response.authenticatorData`, already decoded.
    pub authenticator_data: Vec<u8>,
    /// Assertion signature, already decoded. Empty during attestation `none`.
    pub signature: Vec<u8>,
    /// SPKI public key from `getPublicKey()`, required when registering.
    pub public_key_spki: Option<Vec<u8>>,
}

/// A stored passkey.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    /// Credential id, base64url.
    pub credential_id: String,
    /// SPKI bytes, base64url, as stored.
    pub public_key_spki: String,
    /// Last signature counter. Zero means the authenticator does not count.
    pub signature_counter: u32,
}

/// Checks a new passkey before it is stored.
///
/// Attestation is `none`, so there is no attestation signature. The checks
/// are the ceremony binding (challenge, origin, rp id) and the user-verified
/// flag. The following sign-in proves possession of the private key.
pub fn verify_registration(
    expected: &ExpectedCeremony,
    response: &CeremonyResponse,
) -> Result<String, WebAuthnError> {
    if expected.ceremony_type != "webauthn.create" {
        return Err(WebAuthnError::Mismatch);
    }
    check_binding(expected, response)?;
    let spki = response
        .public_key_spki
        .as_deref()
        .ok_or(WebAuthnError::BadSignature)?;
    VerifyingKey::from_public_key_der(spki).map_err(|_| WebAuthnError::BadSignature)?;
    Ok(URL_SAFE_NO_PAD.encode(spki))
}

/// Checks a sign-in assertion and returns the counter to store.
pub fn verify_authentication(
    expected: &ExpectedCeremony,
    response: &CeremonyResponse,
    passkey: &StoredPasskey,
) -> Result<u32, WebAuthnError> {
    if expected.ceremony_type != "webauthn.get" {
        return Err(WebAuthnError::Mismatch);
    }
    let counter = check_binding(expected, response)?;
    if passkey.signature_counter > 0 && counter <= passkey.signature_counter {
        return Err(WebAuthnError::CounterRewound);
    }
    let spki = URL_SAFE_NO_PAD
        .decode(passkey.public_key_spki.as_bytes())
        .map_err(|_| WebAuthnError::BadSignature)?;
    let key = VerifyingKey::from_public_key_der(&spki).map_err(|_| WebAuthnError::BadSignature)?;
    let signature =
        Signature::from_der(&response.signature).map_err(|_| WebAuthnError::BadSignature)?;
    let mut signed = response.authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&response.client_data_json));
    key.verify(&signed, &signature)
        .map_err(|_| WebAuthnError::BadSignature)?;
    Ok(counter)
}

/// Returns a fresh base64url challenge.
pub fn new_challenge() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("random challenge");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Returns the expiry for a challenge created at `now_ms`.
pub fn challenge_expiry(now_ms: i64) -> i64 {
    now_ms + CHALLENGE_TTL_MS
}

fn check_binding(
    expected: &ExpectedCeremony,
    response: &CeremonyResponse,
) -> Result<u32, WebAuthnError> {
    let client: serde_json::Value =
        serde_json::from_slice(&response.client_data_json).map_err(|_| WebAuthnError::Malformed)?;
    let kind = client.get("type").and_then(|v| v.as_str());
    let challenge = client.get("challenge").and_then(|v| v.as_str());
    let origin = client.get("origin").and_then(|v| v.as_str());
    if kind != Some(expected.ceremony_type)
        || challenge != Some(expected.challenge.as_str())
        || origin != Some(expected.origin.as_str())
    {
        return Err(WebAuthnError::Mismatch);
    }
    if response.authenticator_data.len() < 37 {
        return Err(WebAuthnError::Malformed);
    }
    let rp_hash = Sha256::digest(expected.rp_id.as_bytes());
    if response.authenticator_data[..32] != rp_hash[..] {
        return Err(WebAuthnError::Mismatch);
    }
    let flags = response.authenticator_data[32];
    let user_present = flags & 0x01 != 0;
    let user_verified = flags & 0x04 != 0;
    if !user_present || !user_verified {
        return Err(WebAuthnError::UserNotVerified);
    }
    let counter = u32::from_be_bytes(response.authenticator_data[33..37].try_into().unwrap());
    Ok(counter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;
    use rand::rngs::OsRng;

    fn authenticator_data(rp_id: &str, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(0x01 | 0x04);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    #[test]
    fn registration_accepts_a_bound_verified_key() {
        let key = SigningKey::random(&mut OsRng);
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let challenge = new_challenge();
        let client = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"http://localhost:5173"}}"#
        );
        let response = CeremonyResponse {
            client_data_json: client.into_bytes(),
            authenticator_data: authenticator_data("localhost", 0),
            signature: Vec::new(),
            public_key_spki: Some(spki),
        };
        let expected = ExpectedCeremony {
            ceremony_type: "webauthn.create",
            challenge,
            origin: "http://localhost:5173".to_string(),
            rp_id: "localhost".to_string(),
        };
        assert!(verify_registration(&expected, &response).is_ok());
    }

    #[test]
    fn registration_rejects_the_wrong_origin() {
        let key = SigningKey::random(&mut OsRng);
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let challenge = new_challenge();
        let client = format!(
            r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"https://evil.example"}}"#
        );
        let response = CeremonyResponse {
            client_data_json: client.into_bytes(),
            authenticator_data: authenticator_data("localhost", 0),
            signature: Vec::new(),
            public_key_spki: Some(spki),
        };
        let expected = ExpectedCeremony {
            ceremony_type: "webauthn.create",
            challenge,
            origin: "http://localhost:5173".to_string(),
            rp_id: "localhost".to_string(),
        };
        assert_eq!(
            verify_registration(&expected, &response),
            Err(WebAuthnError::Mismatch)
        );
    }

    #[test]
    fn authentication_accepts_a_matching_signature() {
        let key = SigningKey::random(&mut OsRng);
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let challenge = new_challenge();
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:5173"}}"#
        );
        let client_data_json = client.into_bytes();
        let authenticator_data = authenticator_data("localhost", 2);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature: Signature = key.sign(&signed);
        let response = CeremonyResponse {
            client_data_json,
            authenticator_data,
            signature: signature.to_der().as_bytes().to_vec(),
            public_key_spki: None,
        };
        let passkey = StoredPasskey {
            credential_id: "cred".to_string(),
            public_key_spki: URL_SAFE_NO_PAD.encode(spki),
            signature_counter: 1,
        };
        let expected = ExpectedCeremony {
            ceremony_type: "webauthn.get",
            challenge,
            origin: "http://localhost:5173".to_string(),
            rp_id: "localhost".to_string(),
        };
        assert_eq!(verify_authentication(&expected, &response, &passkey), Ok(2));
    }

    #[test]
    fn authentication_rejects_a_rewound_counter() {
        let key = SigningKey::random(&mut OsRng);
        let spki = key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let challenge = new_challenge();
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:5173"}}"#
        );
        let client_data_json = client.into_bytes();
        let authenticator_data = authenticator_data("localhost", 1);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature: Signature = key.sign(&signed);
        let response = CeremonyResponse {
            client_data_json,
            authenticator_data,
            signature: signature.to_der().as_bytes().to_vec(),
            public_key_spki: None,
        };
        let passkey = StoredPasskey {
            credential_id: "cred".to_string(),
            public_key_spki: URL_SAFE_NO_PAD.encode(spki),
            signature_counter: 4,
        };
        let expected = ExpectedCeremony {
            ceremony_type: "webauthn.get",
            challenge,
            origin: "http://localhost:5173".to_string(),
            rp_id: "localhost".to_string(),
        };
        assert_eq!(
            verify_authentication(&expected, &response, &passkey),
            Err(WebAuthnError::CounterRewound)
        );
    }
}
