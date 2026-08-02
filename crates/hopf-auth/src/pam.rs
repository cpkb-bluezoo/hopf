// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`PamCredentialStore`] — system PAM password verification.
//!
//! Enabled with Cargo feature `pam` (Unix). Talks to `libpam` / OpenPAM via
//! thin FFI (no bindgen / external PAM crates).
//!
//! # Reactor safety
//!
//! [`CredentialStore::password_match`](crate::CredentialStore::password_match)
//! **must not** run on a Hopf reactor thread. PAM calls are blocking; invoke
//! from a storage/worker pool (same rule as LDAP).

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Arc;

use crate::mechanism::SaslMechanism;
use crate::store::{
    CertificateIdentity, CredentialStore, ScramCredentials, TokenValidation,
};

/// Default PAM service name when none is configured.
pub const DEFAULT_PAM_SERVICE: &str = "login";

// ── Minimal PAM FFI (Linux-PAM / OpenPAM) ─────────────────────────────────────

const PAM_SUCCESS: c_int = 0;
const PAM_CONV_ERR: c_int = 6;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *mut *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

enum PamHandle {}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> c_int;

    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut PamHandle, pam_status: c_int) -> c_int;
}

struct ConvData {
    password: CString,
}

unsafe extern "C" fn password_conv(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata_ptr.is_null() {
        return PAM_CONV_ERR;
    }
    let data = &*(appdata_ptr as *const ConvData);
    let n = num_msg as usize;
    let responses = libc::calloc(n, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
    if responses.is_null() {
        return PAM_CONV_ERR;
    }
    for i in 0..n {
        let m = *msg.add(i);
        if m.is_null() {
            for j in 0..i {
                let r = &mut *responses.add(j);
                if !r.resp.is_null() {
                    libc::free(r.resp as *mut c_void);
                }
            }
            libc::free(responses as *mut c_void);
            return PAM_CONV_ERR;
        }
        let style = (*m).msg_style;
        let r = &mut *responses.add(i);
        r.resp_retcode = 0;
        r.resp = match style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => libc::strdup(data.password.as_ptr()),
            PAM_ERROR_MSG | PAM_TEXT_INFO => ptr::null_mut(),
            _ => {
                for j in 0..=i {
                    let rj = &mut *responses.add(j);
                    if !rj.resp.is_null() {
                        libc::free(rj.resp as *mut c_void);
                    }
                }
                libc::free(responses as *mut c_void);
                return PAM_CONV_ERR;
            }
        };
    }
    *resp = responses;
    PAM_SUCCESS
}

fn pam_password_match(service: &str, username: &str, password: &str) -> bool {
    let Ok(service_c) = CString::new(service) else {
        return false;
    };
    let Ok(user_c) = CString::new(username) else {
        return false;
    };
    let Ok(password_c) = CString::new(password) else {
        return false;
    };

    let mut conv_data = ConvData {
        password: password_c,
    };
    let conv = PamConv {
        conv: Some(password_conv),
        appdata_ptr: &mut conv_data as *mut ConvData as *mut c_void,
    };

    let mut pamh: *mut PamHandle = ptr::null_mut();
    let mut status = unsafe {
        pam_start(
            service_c.as_ptr(),
            user_c.as_ptr(),
            &conv,
            &mut pamh,
        )
    };
    if status != PAM_SUCCESS || pamh.is_null() {
        return false;
    }

    status = unsafe { pam_authenticate(pamh, 0) };
    if status == PAM_SUCCESS {
        status = unsafe { pam_acct_mgmt(pamh, 0) };
    }
    let ok = status == PAM_SUCCESS;
    unsafe {
        pam_end(pamh, status);
    }
    ok
}

// ── Public store ──────────────────────────────────────────────────────────────

/// Configuration for [`PamCredentialStore`].
#[derive(Debug, Clone)]
pub struct PamStoreConfig {
    /// PAM service name (e.g. `login`, `sshd`, or a custom `hopf` stack).
    pub service: String,
}

impl Default for PamStoreConfig {
    fn default() -> Self {
        Self {
            service: DEFAULT_PAM_SERVICE.into(),
        }
    }
}

impl PamStoreConfig {
    /// Config with the given PAM service name.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

/// [`CredentialStore`] backed by system PAM (PLAIN / LOGIN only).
///
/// Flow: `pam_start` → conversation supplies password → `pam_authenticate` →
/// `pam_acct_mgmt` → `pam_end`. No session open.
#[derive(Debug, Clone)]
pub struct PamCredentialStore {
    config: PamStoreConfig,
}

impl PamCredentialStore {
    /// Create a store for `service` (see [`DEFAULT_PAM_SERVICE`]).
    pub fn new(config: PamStoreConfig) -> Self {
        Self { config }
    }

    /// Convenience: service name only.
    pub fn with_service(service: impl Into<String>) -> Self {
        Self::new(PamStoreConfig::new(service))
    }

    /// Shared trait object.
    pub fn shared(self) -> Arc<dyn CredentialStore> {
        Arc::new(self)
    }

    /// PAM service name in use.
    pub fn service(&self) -> &str {
        &self.config.service
    }
}

impl CredentialStore for PamCredentialStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        vec![SaslMechanism::Plain, SaslMechanism::Login]
    }

    /// Verify username/password via PAM. **Must not run on a reactor thread.**
    fn password_match(&self, username: &str, password: &str) -> bool {
        if username.is_empty() {
            return false;
        }
        pam_password_match(&self.config.service, username, password)
    }

    fn plaintext_password(&self, _username: &str) -> Option<String> {
        None
    }

    fn digest_ha1(&self, _username: &str, _realm: &str) -> Option<String> {
        None
    }

    fn scram_credentials(&self, _username: &str) -> Option<ScramCredentials> {
        None
    }

    fn validate_bearer(&self, _token: &str) -> Option<TokenValidation> {
        None
    }

    fn authenticate_certificate(&self, _cert_key: &str) -> Option<CertificateIdentity> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_mechanisms_plain_login_only() {
        let store = PamCredentialStore::with_service("login");
        assert_eq!(
            store.supported_mechanisms(),
            vec![SaslMechanism::Plain, SaslMechanism::Login]
        );
        assert!(store.digest_ha1("u", "r").is_none());
        assert!(store.scram_credentials("u").is_none());
        assert!(store.plaintext_password("u").is_none());
        assert!(store.validate_bearer("t").is_none());
        assert_eq!(store.service(), "login");
    }

    #[test]
    fn empty_username_rejected_without_pam_roundtrip() {
        let store = PamCredentialStore::with_service("login");
        assert!(!store.password_match("", "x"));
    }
}
