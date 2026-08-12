// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL SCRAM-SHA-256 / SCRAM-SHA-256-PLUS (RFC 5802 / RFC 7677 / RFC 5929).
//!
//! Channel binding uses the `tls-server-end-point` type (RFC 5929 §4): a
//! hash of the server's TLS certificate. This module has no TLS awareness
//! of its own — the caller (the protocol crate that owns the live TLS
//! connection) computes that hash from the negotiated certificate and
//! supplies it via [`ScramSha256Client::new_plus`] /
//! [`ScramSha256Server::with_channel_binding`], the same way
//! [`crate::external::ExternalServer::with_peer_certificate`] is supplied
//! peer-certificate material for EXTERNAL.
//!
//! Scope note: this defends against a MITM relaying the SASL exchange
//! across two different TLS connections (the property channel binding
//! exists for) by having the server independently recompute the expected
//! `c=` value and reject a mismatch, rather than trusting whatever bytes
//! the client sent. It does *not* implement cross-mechanism downgrade
//! detection (RFC 5802bis §6's "the client remembers whether the server
//! advertised PLUS variants and fails if a MITM stripped them") — that
//! requires the SASL mechanism-list/session layer to track what was
//! advertised, which is a separate, broader concern than this single
//! mechanism module.

use std::sync::Arc;

use crate::crypto::{
    ct_eq, decode_base64, encode_base64, generate_nonce_hex, hmac_sha256, sha256,
};
use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::{CredentialStore, ScramCredentials};

/// GS2 header for the channel-binding type this crate supports.
const GS2_HEADER_PLUS: &str = "p=tls-server-end-point,,";
/// GS2 header for a client/server not using channel binding.
const GS2_HEADER_PLAIN: &str = "n,,";

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
///
/// `expected_channel_binding`, when `Some`, is the exact bytes the
/// client's `c=` attribute must base64-decode to (gs2-header as the client
/// sent it, concatenated with the server's own `tls-server-end-point`
/// data) — the real channel-binding check. `None` skips it entirely,
/// matching plain SCRAM-SHA-256's behavior (no channel binding in play).
pub fn verify_client_final(
    creds: &ScramCredentials,
    auth_message_prefix: &str,
    client_final: &str,
    expected_nonce: &str,
    expected_channel_binding: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let attrs = attr_map(client_final);
    let nonce = attrs.get("r")?;
    let proof_b64 = attrs.get("p")?;
    if nonce != expected_nonce {
        return None;
    }
    if let Some(expected_cb) = expected_channel_binding {
        let cbind_b64 = attrs.get("c")?;
        let actual_cb = decode_base64(cbind_b64)?;
        if !ct_eq(&actual_cb, expected_cb) {
            return None;
        }
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
    /// `Some` (this connection's `tls-server-end-point` data) => this is a
    /// SCRAM-SHA-256-PLUS server; `None` => plain SCRAM-SHA-256.
    channel_binding: Option<Vec<u8>>,
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
        /// The GS2 header exactly as the client sent it — required
        /// verbatim to reconstruct the expected `c=` value.
        gs2_header: String,
    },
    Done,
}

impl ScramSha256Server {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self {
            store,
            channel_binding: None,
            state: ScramServerState::Start,
        }
    }

    /// Enable SCRAM-SHA-256-PLUS: `channel_binding` is this connection's
    /// `tls-server-end-point` data (RFC 5929 §4) — the caller computes it
    /// from the certificate actually presented over the live TLS
    /// connection.
    pub fn with_channel_binding(mut self, channel_binding: Vec<u8>) -> Self {
        self.channel_binding = Some(channel_binding);
        self
    }

    fn is_plus(&self) -> bool {
        self.channel_binding.is_some()
    }
}

impl SaslServer for ScramSha256Server {
    fn mechanism(&self) -> SaslMechanism {
        if self.is_plus() {
            SaslMechanism::ScramSha256Plus
        } else {
            SaslMechanism::ScramSha256
        }
    }

    fn step(&mut self, client_response: Option<&[u8]>, cb: crate::session::Cb<SaslServerStep>) {
        match &self.state {
            ScramServerState::Start => {
                let Some(raw) = client_response else {
                    return cb(SaslServerStep::Failure);
                };
                let text = String::from_utf8_lossy(raw);
                // n,,n=user,r=clientnonce  or  p=tls-server-end-point,,n=user,r=…
                // The GS2 header itself never contains a literal "n=" for
                // either form this crate produces, so splitting there is
                // safe and avoids a full GS2 grammar parser.
                let Some(bare_idx) = text.find("n=") else {
                    return cb(SaslServerStep::Failure);
                };
                let gs2_header = text[..bare_idx].to_string();
                let expected_gs2 = if self.is_plus() {
                    GS2_HEADER_PLUS
                } else {
                    GS2_HEADER_PLAIN
                };
                if gs2_header != expected_gs2 {
                    return cb(SaslServerStep::Failure);
                }
                let bare = text[bare_idx..].to_string();
                let attrs = attr_map(&bare);
                let Some(username) = attrs.get("n").cloned() else {
                    return cb(SaslServerStep::Failure);
                };
                // SASLprep omitted; decode =2C etc. minimally
                let username = username.replace("=2C", ",").replace("=3D", "=");
                let Some(client_nonce) = attrs.get("r").cloned() else {
                    return cb(SaslServerStep::Failure);
                };
                let Some(creds) = self.store.scram_credentials(&username) else {
                    return cb(SaslServerStep::Failure);
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
                    gs2_header,
                };
                cb(SaslServerStep::Challenge(challenge));
            }
            ScramServerState::First {
                username,
                client_first_bare,
                server_first,
                combined_nonce,
                creds,
                gs2_header,
            } => {
                let Some(raw) = client_response else {
                    return cb(SaslServerStep::Failure);
                };
                let client_final = String::from_utf8_lossy(raw);
                let auth_prefix = format!("{client_first_bare},{server_first}");
                let expected_cb: Option<Vec<u8>> = self.channel_binding.as_ref().map(|cb| {
                    let mut v = gs2_header.clone().into_bytes();
                    v.extend_from_slice(cb);
                    v
                });
                match verify_client_final(
                    creds,
                    &auth_prefix,
                    &client_final,
                    combined_nonce,
                    expected_cb.as_deref(),
                ) {
                    Some(sig) => {
                        let v = encode_base64(&sig);
                        let user = username.clone();
                        self.state = ScramServerState::Done;
                        cb(SaslServerStep::Complete {
                            username: user,
                            final_message: Some(format!("v={v}").into_bytes()),
                        });
                    }
                    None => {
                        self.state = ScramServerState::Done;
                        cb(SaslServerStep::Failure);
                    }
                }
            }
            ScramServerState::Done => cb(SaslServerStep::Failure),
        }
    }
}

pub(crate) struct ScramSha256Client {
    password: String,
    client_nonce: String,
    client_first_bare: String,
    server_first: String,
    gs2_header: String,
    /// `Some` => SCRAM-SHA-256-PLUS, carrying this connection's
    /// `tls-server-end-point` data.
    channel_binding: Option<Vec<u8>>,
    salted: Option<[u8; 32]>,
    complete: bool,
    step: u8,
}

impl ScramSha256Client {
    pub fn new(username: &str, password: &str) -> Self {
        Self::build(username, password, None)
    }

    /// SCRAM-SHA-256-PLUS: `channel_binding` is this connection's
    /// `tls-server-end-point` data (RFC 5929 §4), computed by the caller
    /// from the server certificate it actually negotiated TLS with.
    pub fn new_plus(username: &str, password: &str, channel_binding: Vec<u8>) -> Self {
        Self::build(username, password, Some(channel_binding))
    }

    fn build(username: &str, password: &str, channel_binding: Option<Vec<u8>>) -> Self {
        let client_nonce = generate_nonce_hex(12);
        let escaped = username.replace(',', "=2C").replace('=', "=3D");
        let client_first_bare = format!("n={escaped},r={client_nonce}");
        let gs2_header = if channel_binding.is_some() {
            GS2_HEADER_PLUS.to_string()
        } else {
            GS2_HEADER_PLAIN.to_string()
        };
        Self {
            password: password.into(),
            client_nonce,
            client_first_bare,
            server_first: String::new(),
            gs2_header,
            channel_binding,
            salted: None,
            complete: false,
            step: 0,
        }
    }

    fn is_plus(&self) -> bool {
        self.channel_binding.is_some()
    }
}

impl SaslClient for ScramSha256Client {
    fn mechanism(&self) -> SaslMechanism {
        if self.is_plus() {
            SaslMechanism::ScramSha256Plus
        } else {
            SaslMechanism::ScramSha256
        }
    }

    fn has_initial_response(&self) -> bool {
        true
    }

    fn evaluate(&mut self, challenge: Option<&[u8]>) -> SaslClientStep {
        if self.step == 0 {
            self.step = 1;
            let msg = format!("{}{}", self.gs2_header, self.client_first_bare);
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
            let mut cbind_input = self.gs2_header.clone().into_bytes();
            if let Some(cb) = &self.channel_binding {
                cbind_input.extend_from_slice(cb);
            }
            let channel_binding_b64 = encode_base64(&cbind_input);
            let client_final_without_proof = format!("c={channel_binding_b64},r={combined}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PasswordStore;

    fn store_with(user: &str, pass: &str) -> Arc<dyn CredentialStore> {
        Arc::new(PasswordStore::new().with_user(user, pass))
    }

    /// Drive a full client/server exchange to completion (or the first
    /// failure), returning the final username on success.
    fn run(
        mut client: Box<dyn SaslClient>,
        mut server: Box<dyn SaslServer>,
    ) -> Result<String, ()> {
        let mut client_msg = match client.evaluate(None) {
            SaslClientStep::Response(b) | SaslClientStep::Complete(b) => Some(b),
            SaslClientStep::Failure => return Err(()),
        };
        for _ in 0..8 {
            let (tx, rx) = std::sync::mpsc::channel();
            server.step(client_msg.as_deref(), Box::new(move |s| { let _ = tx.send(s); }));
            match rx.recv().expect("step completes synchronously in tests") {
                SaslServerStep::Challenge(ch) => match client.evaluate(Some(&ch)) {
                    SaslClientStep::Response(b) | SaslClientStep::Complete(b) => {
                        client_msg = if b.is_empty() { None } else { Some(b) };
                    }
                    SaslClientStep::Failure => return Err(()),
                },
                SaslServerStep::Complete {
                    username,
                    final_message,
                } => {
                    if let Some(fin) = final_message {
                        let _ = client.evaluate(Some(&fin));
                    }
                    return Ok(username);
                }
                SaslServerStep::Failure => return Err(()),
            }
        }
        Err(())
    }

    #[test]
    fn plain_scram_still_works_without_channel_binding() {
        let store = store_with("alice", "s3cret");
        let client: Box<dyn SaslClient> =
            Box::new(ScramSha256Client::new("alice", "s3cret"));
        let server: Box<dyn SaslServer> = Box::new(ScramSha256Server::new(store));
        assert_eq!(run(client, server), Ok("alice".to_string()));
    }

    #[test]
    fn plus_variant_reports_the_plus_mechanism_name() {
        let client = ScramSha256Client::new_plus("alice", "s3cret", vec![1, 2, 3]);
        let server = ScramSha256Server::new(store_with("alice", "s3cret"))
            .with_channel_binding(vec![1, 2, 3]);
        assert_eq!(client.mechanism(), SaslMechanism::ScramSha256Plus);
        assert_eq!(server.mechanism(), SaslMechanism::ScramSha256Plus);
        assert_eq!(SaslMechanism::ScramSha256Plus.name(), "SCRAM-SHA-256-PLUS");
    }

    #[test]
    fn plus_succeeds_when_client_and_server_agree_on_channel_binding_data() {
        let store = store_with("alice", "s3cret");
        let cb_data = vec![0xAB; 32]; // stand-in for a real cert hash
        let client: Box<dyn SaslClient> =
            Box::new(ScramSha256Client::new_plus("alice", "s3cret", cb_data.clone()));
        let server: Box<dyn SaslServer> = Box::new(
            ScramSha256Server::new(store).with_channel_binding(cb_data),
        );
        assert_eq!(run(client, server), Ok("alice".to_string()));
    }

    /// The core security property: if the client's and server's view of
    /// the TLS channel-binding data disagree (as they would if a MITM
    /// relayed the exchange across two different TLS connections), the
    /// exchange must fail even though the client has the correct password.
    #[test]
    fn plus_fails_when_channel_binding_data_disagrees() {
        let store = store_with("alice", "s3cret");
        let client: Box<dyn SaslClient> = Box::new(ScramSha256Client::new_plus(
            "alice",
            "s3cret",
            vec![0xAA; 32],
        ));
        let server: Box<dyn SaslServer> = Box::new(
            ScramSha256Server::new(store).with_channel_binding(vec![0xBB; 32]),
        );
        assert_eq!(run(client, server), Err(()));
    }

    #[test]
    fn plus_client_against_plain_server_fails_gs2_header_check() {
        let store = store_with("alice", "s3cret");
        let client: Box<dyn SaslClient> = Box::new(ScramSha256Client::new_plus(
            "alice",
            "s3cret",
            vec![1, 2, 3],
        ));
        let server: Box<dyn SaslServer> = Box::new(ScramSha256Server::new(store));
        assert_eq!(run(client, server), Err(()));
    }

    #[test]
    fn plain_client_against_plus_server_fails_gs2_header_check() {
        let store = store_with("alice", "s3cret");
        let client: Box<dyn SaslClient> = Box::new(ScramSha256Client::new("alice", "s3cret"));
        let server: Box<dyn SaslServer> = Box::new(
            ScramSha256Server::new(store).with_channel_binding(vec![1, 2, 3]),
        );
        assert_eq!(run(client, server), Err(()));
    }

    #[test]
    fn wrong_password_still_fails_with_channel_binding_enabled() {
        let store = store_with("alice", "s3cret");
        let cb_data = vec![7u8; 16];
        let client: Box<dyn SaslClient> = Box::new(ScramSha256Client::new_plus(
            "alice",
            "wrong-password",
            cb_data.clone(),
        ));
        let server: Box<dyn SaslServer> = Box::new(
            ScramSha256Server::new(store).with_channel_binding(cb_data),
        );
        assert_eq!(run(client, server), Err(()));
    }
}
