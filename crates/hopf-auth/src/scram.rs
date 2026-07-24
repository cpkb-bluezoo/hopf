// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL SCRAM-SHA-256 (RFC 5802 / RFC 7677).

use std::sync::Arc;

use crate::crypto::{
    ct_eq, decode_base64, encode_base64, generate_nonce_hex, hmac_sha256, sha256,
};
use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::{CredentialStore, ScramCredentials};

fn attr_map(s: &str) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for part in s.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            m.insert(k.to_string(), v.to_string());
        }
    }
    m
}

/// Verify client-final; returns server signature bytes (Gumdrop `verifyScramClientFinal`).
pub fn verify_client_final(
    creds: &ScramCredentials,
    auth_message_prefix: &str,
    client_final: &str,
    expected_nonce: &str,
) -> Option<Vec<u8>> {
    let attrs = attr_map(client_final);
    let nonce = attrs.get("r")?;
    let proof_b64 = attrs.get("p")?;
    if nonce != expected_nonce {
        return None;
    }
    let proof_idx = client_final.rfind(",p=")?;
    let client_final_without_proof = &client_final[..proof_idx];
    let auth_message = format!("{auth_message_prefix},{client_final_without_proof}");
    let client_signature = hmac_sha256(&creds.stored_key, auth_message.as_bytes());
    let client_proof = decode_base64(proof_b64)?;
    if client_proof.len() != client_signature.len() {
        return None;
    }
    let mut recovered = vec![0u8; client_proof.len()];
    for i in 0..client_proof.len() {
        recovered[i] = client_proof[i] ^ client_signature[i];
    }
    let computed_stored = sha256(&recovered);
    if !ct_eq(&computed_stored, &creds.stored_key) {
        return None;
    }
    Some(hmac_sha256(&creds.server_key, auth_message.as_bytes()))
}

pub(crate) struct ScramSha256Server {
    store: Arc<dyn CredentialStore>,
    state: ScramServerState,
}

enum ScramServerState {
    Start,
    First {
        username: String,
        client_first_bare: String,
        server_first: String,
        combined_nonce: String,
        creds: ScramCredentials,
    },
    Done,
}

impl ScramSha256Server {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self {
            store,
            state: ScramServerState::Start,
        }
    }
}

impl SaslServer for ScramSha256Server {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::ScramSha256
    }

    fn step(&mut self, client_response: Option<&[u8]>) -> SaslServerStep {
        match &self.state {
            ScramServerState::Start => {
                let Some(raw) = client_response else {
                    return SaslServerStep::Failure;
                };
                let text = String::from_utf8_lossy(raw);
                // n,,n=user,r=clientnonce  or  y,,n=user,r=…
                let bare = text
                    .find("n=")
                    .map(|i| text[i..].to_string())
                    .unwrap_or_else(|| text.to_string());
                let attrs = attr_map(&bare);
                let Some(username) = attrs.get("n").cloned() else {
                    return SaslServerStep::Failure;
                };
                // SASLprep omitted; decode =2C etc. minimally
                let username = username.replace("=2C", ",").replace("=3D", "=");
                let Some(client_nonce) = attrs.get("r").cloned() else {
                    return SaslServerStep::Failure;
                };
                let Some(creds) = self.store.scram_credentials(&username) else {
                    return SaslServerStep::Failure;
                };
                let server_nonce = generate_nonce_hex(12);
                let combined = format!("{client_nonce}{server_nonce}");
                let server_first = format!(
                    "r={combined},s={},i={}",
                    creds.salt_b64, creds.iterations
                );
                let challenge = server_first.clone().into_bytes();
                self.state = ScramServerState::First {
                    username,
                    client_first_bare: bare,
                    server_first,
                    combined_nonce: combined,
                    creds,
                };
                SaslServerStep::Challenge(challenge)
            }
            ScramServerState::First {
                username,
                client_first_bare,
                server_first,
                combined_nonce,
                creds,
            } => {
                let Some(raw) = client_response else {
                    return SaslServerStep::Failure;
                };
                let client_final = String::from_utf8_lossy(raw);
                let auth_prefix = format!("{client_first_bare},{server_first}");
                match verify_client_final(creds, &auth_prefix, &client_final, combined_nonce) {
                    Some(sig) => {
                        let v = encode_base64(&sig);
                        let user = username.clone();
                        self.state = ScramServerState::Done;
                        SaslServerStep::Complete {
                            username: user,
                            final_message: Some(format!("v={v}").into_bytes()),
                        }
                    }
                    None => {
                        self.state = ScramServerState::Done;
                        SaslServerStep::Failure
                    }
                }
            }
            ScramServerState::Done => SaslServerStep::Failure,
        }
    }
}

pub(crate) struct ScramSha256Client {
    password: String,
    client_nonce: String,
    client_first_bare: String,
    server_first: String,
    salted: Option<[u8; 32]>,
    complete: bool,
    step: u8,
}

impl ScramSha256Client {
    pub fn new(username: &str, password: &str) -> Self {
        let client_nonce = generate_nonce_hex(12);
        let escaped = username.replace(',', "=2C").replace('=', "=3D");
        let client_first_bare = format!("n={escaped},r={client_nonce}");
        Self {
            password: password.into(),
            client_nonce,
            client_first_bare,
            server_first: String::new(),
            salted: None,
            complete: false,
            step: 0,
        }
    }
}

impl SaslClient for ScramSha256Client {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::ScramSha256
    }

    fn has_initial_response(&self) -> bool {
        true
    }

    fn evaluate(&mut self, challenge: Option<&[u8]>) -> SaslClientStep {
        if self.step == 0 {
            self.step = 1;
            let msg = format!("n,,{}", self.client_first_bare);
            return SaslClientStep::Response(msg.into_bytes());
        }
        if self.step == 1 {
            let Some(ch) = challenge else {
                return SaslClientStep::Failure;
            };
            self.server_first = String::from_utf8_lossy(ch).into_owned();
            let attrs = attr_map(&self.server_first);
            let Some(combined) = attrs.get("r") else {
                return SaslClientStep::Failure;
            };
            if !combined.starts_with(&self.client_nonce) {
                return SaslClientStep::Failure;
            }
            let Some(salt_b64) = attrs.get("s") else {
                return SaslClientStep::Failure;
            };
            let Some(iter_s) = attrs.get("i") else {
                return SaslClientStep::Failure;
            };
            let Ok(iterations) = iter_s.parse::<u32>() else {
                return SaslClientStep::Failure;
            };
            let Some(salt) = decode_base64(salt_b64) else {
                return SaslClientStep::Failure;
            };
            let salted =
                crate::crypto::pbkdf2_sha256(self.password.as_bytes(), &salt, iterations);
            self.salted = Some(salted);
            let client_key = hmac_sha256(&salted, b"Client Key");
            let stored_key = sha256(&client_key);
            let channel_binding = "c=biws"; // n,, base64
            let client_final_without_proof = format!("{channel_binding},r={combined}");
            let auth_message = format!(
                "{},{},{}",
                self.client_first_bare, self.server_first, client_final_without_proof
            );
            let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
            let mut proof = client_key;
            for i in 0..proof.len() {
                proof[i] ^= client_signature[i];
            }
            let msg = format!(
                "{client_final_without_proof},p={}",
                encode_base64(&proof)
            );
            self.step = 2;
            return SaslClientStep::Complete(msg.into_bytes());
        }
        // optional verify v=
        if let Some(ch) = challenge {
            let t = String::from_utf8_lossy(ch);
            if t.starts_with("v=") {
                self.complete = true;
                return SaslClientStep::Complete(Vec::new());
            }
        }
        self.complete = true;
        SaslClientStep::Complete(Vec::new())
    }

    fn is_complete(&self) -> bool {
        self.complete || self.step >= 2
    }
}
