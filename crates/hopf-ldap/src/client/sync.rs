// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAP Content Synchronization (RFC 4533, "syncrepl"): the value types of the
//! Sync Request / Sync State / Sync Done controls and the Sync Info
//! intermediate response, and the events a sync operation delivers.
//!
//! A sync operation is an ordinary search carrying a Sync Request Control
//! ([`SyncRequest`]). The server answers with entries each tagged by a Sync
//! State Control ([`SyncStateValue`]), Sync Info messages ([`SyncInfo`])
//! that carry cookies and delimit refresh phases, and - for `refreshOnly`, or
//! when a `refreshAndPersist` search ends - a SearchResultDone with a Sync
//! Done Control ([`SyncDoneValue`]). [`super::LdapSession::sync`] parses all of
//! that into [`SyncEvent`]s; [`super::SyncReplica`] applies them to a local
//! copy of the content.

use crate::{Asn1Element, Asn1Error, Asn1Type, BerDecoder, BerEncoder};

use super::control::Control;
use super::types::{LdapResultCode, SearchEntry};

/// Sync Request Control OID (RFC 4533 section 2.2).
pub const OID_SYNC_REQUEST_CONTROL: &str = "1.3.6.1.4.1.4203.1.9.1.1";
/// Sync State Control OID (section 2.3).
pub const OID_SYNC_STATE_CONTROL: &str = "1.3.6.1.4.1.4203.1.9.1.2";
/// Sync Done Control OID (section 2.4).
pub const OID_SYNC_DONE_CONTROL: &str = "1.3.6.1.4.1.4203.1.9.1.3";
/// Sync Info Message OID (section 2.5): the `responseName` of the
/// IntermediateResponse.
pub const OID_SYNC_INFO_MESSAGE: &str = "1.3.6.1.4.1.4203.1.9.1.4";

/// Length of a `syncUUID` (section 2.1.1).
pub const SYNC_UUID_LEN: usize = 16;

/// Which kind of synchronisation a Sync Request asks for (section 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncMode {
    /// A poll: the server sends the changes since the cookie and the search
    /// ends (`refreshOnly`, 1).
    RefreshOnly,
    /// Changes since the cookie, then change notifications for as long as the
    /// search stays open (`refreshAndPersist`, 3).
    RefreshAndPersist,
}

impl SyncMode {
    fn value(self) -> i32 {
        match self {
            Self::RefreshOnly => 1,
            Self::RefreshAndPersist => 3,
        }
    }
}

/// The Sync Request Control's value (`syncRequestValue`, section 2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    /// Poll or listen.
    pub mode: SyncMode,
    /// The newest cookie received from the server, to resume from; `None` for
    /// an initial synchronisation.
    pub cookie: Option<Vec<u8>>,
    /// Ask for a full reload, rather than `e-syncRefreshRequired`, when the
    /// server cannot continue incrementally (section 3.3.2).
    pub reload_hint: bool,
    /// Whether the control is critical. Default `true`: without server
    /// support the search would just return everything with no sync state,
    /// which is worthless to a replica.
    pub critical: bool,
}

impl SyncRequest {
    /// An initial synchronisation (no cookie) in `mode`.
    pub fn new(mode: SyncMode) -> Self {
        Self { mode, cookie: None, reload_hint: false, critical: true }
    }

    /// Resume from `cookie`, the newest one the server sent.
    pub fn with_cookie(mut self, cookie: impl Into<Vec<u8>>) -> Self {
        self.cookie = Some(cookie.into());
        self
    }

    /// Set the reload hint.
    pub fn with_reload_hint(mut self, reload_hint: bool) -> Self {
        self.reload_hint = reload_hint;
        self
    }

    /// BER `syncRequestValue`.
    pub fn encode_value(&self) -> Vec<u8> {
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.write_enumerated(self.mode.value());
        if let Some(cookie) = &self.cookie {
            enc.write_octet_string(cookie);
        }
        if self.reload_hint {
            enc.write_boolean(true); // DEFAULT FALSE
        }
        enc.end_sequence();
        enc.into_bytes()
    }

    /// The control to attach to the SearchRequest.
    pub fn to_control(&self) -> Control {
        Control {
            oid: OID_SYNC_REQUEST_CONTROL.into(),
            critical: self.critical,
            value: Some(self.encode_value()),
        }
    }
}

/// An entry's sync state (`syncStateValue.state`, section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncState {
    /// Unchanged since the cookie (an empty entry, in a present phase).
    Present,
    /// Added to the content.
    Add,
    /// Modified within the content.
    Modify,
    /// Removed from the content.
    Delete,
}

/// The Sync State Control on an entry or reference (section 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStateValue {
    /// What happened to this entry.
    pub state: SyncState,
    /// The entry's UUID: the stable key a replica identifies it by (its DN can
    /// change).
    pub entry_uuid: Vec<u8>,
    /// A new cookie, if the server sent one with this entry.
    pub cookie: Option<Vec<u8>>,
}

/// The Sync Done Control on a SearchResultDone (section 2.4).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncDoneValue {
    /// The cookie for the next synchronisation.
    pub cookie: Option<Vec<u8>>,
    /// `true` when the refresh ended with a delete phase (deletions were sent
    /// explicitly); `false` when it ended with a present phase, in which case
    /// any entry not confirmed present is no longer in the content.
    pub refresh_deletes: bool,
}

/// A parsed Sync Info Message (`syncInfoValue`, section 2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncInfo {
    /// A new cookie and nothing else.
    NewCookie(Vec<u8>),
    /// The delete phase of a refresh has ended.
    RefreshDelete {
        /// Cookie for the state after the phase.
        cookie: Option<Vec<u8>>,
        /// The whole refresh is over (`DEFAULT TRUE`).
        refresh_done: bool,
    },
    /// The present phase of a refresh has ended.
    RefreshPresent {
        /// Cookie for the state after the phase.
        cookie: Option<Vec<u8>>,
        /// The whole refresh is over (`DEFAULT TRUE`); `false` when a delete
        /// phase follows.
        refresh_done: bool,
    },
    /// UUIDs whose state the server reports in bulk, in place of one empty
    /// entry each.
    SyncIdSet {
        /// Cookie for the state after this batch.
        cookie: Option<Vec<u8>>,
        /// `true`: these entries were deleted. `false`: they are present
        /// (unchanged).
        refresh_deletes: bool,
        /// The entries' UUIDs.
        entry_uuids: Vec<Vec<u8>>,
    },
}

/// One thing a sync operation reports, in the order the server sent it.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncEvent {
    /// A SearchResultEntry. `state` is `None` if the server sent no (or an
    /// unreadable) Sync State Control, which a compliant server never does.
    Entry {
        /// The entry: empty of attributes for a present or delete.
        entry: SearchEntry,
        /// Its sync state.
        state: Option<SyncStateValue>,
    },
    /// A SearchResultReference (a referral in the content).
    Reference {
        /// The LDAP URLs (empty for a present or delete).
        urls: Vec<String>,
        /// Its sync state.
        state: Option<SyncStateValue>,
    },
    /// A cookie update ([`SyncInfo::NewCookie`]).
    NewCookie(Vec<u8>),
    /// End of a delete phase ([`SyncInfo::RefreshDelete`]).
    RefreshDelete {
        /// Cookie after the phase.
        cookie: Option<Vec<u8>>,
        /// The refresh stage is over.
        refresh_done: bool,
    },
    /// End of a present phase ([`SyncInfo::RefreshPresent`]).
    RefreshPresent {
        /// Cookie after the phase.
        cookie: Option<Vec<u8>>,
        /// The refresh stage is over.
        refresh_done: bool,
    },
    /// A batch of UUIDs ([`SyncInfo::SyncIdSet`]).
    IdSet {
        /// Cookie after the batch.
        cookie: Option<Vec<u8>>,
        /// Deleted (`true`) or present (`false`).
        refresh_deletes: bool,
        /// The UUIDs.
        entry_uuids: Vec<Vec<u8>>,
    },
}

/// How a sync operation ended (SearchResultDone plus its Sync Done Control).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDone {
    /// `Success` for a completed refresh-only poll; [`LdapResultCode::SyncRefreshRequired`]
    /// when the server cannot continue incrementally and the client must
    /// discard its cookie and reload.
    pub result_code: LdapResultCode,
    /// The Sync Done Control's cookie.
    pub cookie: Option<Vec<u8>>,
    /// See [`SyncDoneValue::refresh_deletes`].
    pub refresh_deletes: bool,
    /// Referral URLs from references or the result.
    pub referrals: Vec<String>,
}

fn decode_one(bytes: &[u8]) -> Result<Asn1Element, Asn1Error> {
    let mut dec = BerDecoder::new();
    dec.receive(bytes)?;
    dec.next().ok_or_else(|| Asn1Error::new("empty BER value"))
}

fn octets(e: &Asn1Element) -> Vec<u8> {
    e.as_octet_string().map(<[u8]>::to_vec).unwrap_or_default()
}

impl SyncStateValue {
    /// Parse a `syncStateValue`.
    pub fn parse(value: &[u8]) -> Result<Self, Asn1Error> {
        let seq = decode_one(value)?;
        if seq.tag() != Asn1Type::SEQUENCE || seq.child_count() < 2 {
            return Err(Asn1Error::new("malformed syncStateValue"));
        }
        let state = match seq.child(0).as_i32()? {
            0 => SyncState::Present,
            1 => SyncState::Add,
            2 => SyncState::Modify,
            3 => SyncState::Delete,
            n => return Err(Asn1Error::new(format!("unknown sync state {n}"))),
        };
        let entry_uuid = octets(seq.child(1));
        if entry_uuid.len() != SYNC_UUID_LEN {
            return Err(Asn1Error::new("syncUUID is not 16 octets"));
        }
        let cookie = (seq.child_count() > 2).then(|| octets(seq.child(2)));
        Ok(Self { state, entry_uuid, cookie })
    }
}

impl SyncDoneValue {
    /// Parse a `syncDoneValue`.
    pub fn parse(value: &[u8]) -> Result<Self, Asn1Error> {
        let seq = decode_one(value)?;
        if seq.tag() != Asn1Type::SEQUENCE {
            return Err(Asn1Error::new("malformed syncDoneValue"));
        }
        let mut out = Self::default();
        for i in 0..seq.child_count() {
            let part = seq.child(i);
            if part.tag() == Asn1Type::OCTET_STRING {
                out.cookie = Some(octets(part));
            } else if part.tag() == Asn1Type::BOOLEAN {
                out.refresh_deletes = part.as_bool()?;
            }
        }
        Ok(out)
    }
}

impl SyncInfo {
    /// Parse the `responseValue` of a Sync Info Message.
    pub fn parse(value: &[u8]) -> Result<Self, Asn1Error> {
        let choice = decode_one(value)?;
        match Asn1Type::tag_number(choice.tag()) {
            0 => Ok(Self::NewCookie(octets(&choice))),
            n @ (1 | 2) => {
                let mut cookie = None;
                let mut refresh_done = true; // DEFAULT TRUE
                for i in 0..choice.child_count() {
                    let part = choice.child(i);
                    if part.tag() == Asn1Type::OCTET_STRING {
                        cookie = Some(octets(part));
                    } else if part.tag() == Asn1Type::BOOLEAN {
                        refresh_done = part.as_bool()?;
                    }
                }
                Ok(if n == 1 {
                    Self::RefreshDelete { cookie, refresh_done }
                } else {
                    Self::RefreshPresent { cookie, refresh_done }
                })
            }
            3 => {
                let mut cookie = None;
                let mut refresh_deletes = false; // DEFAULT FALSE
                let mut entry_uuids = Vec::new();
                for i in 0..choice.child_count() {
                    let part = choice.child(i);
                    if part.tag() == Asn1Type::OCTET_STRING {
                        cookie = Some(octets(part));
                    } else if part.tag() == Asn1Type::BOOLEAN {
                        refresh_deletes = part.as_bool()?;
                    } else if part.tag() == Asn1Type::SET {
                        for j in 0..part.child_count() {
                            let uuid = octets(part.child(j));
                            if uuid.len() != SYNC_UUID_LEN {
                                return Err(Asn1Error::new("syncUUID is not 16 octets"));
                            }
                            entry_uuids.push(uuid);
                        }
                    }
                }
                Ok(Self::SyncIdSet { cookie, refresh_deletes, entry_uuids })
            }
            n => Err(Asn1Error::new(format!("unrecognised syncInfoValue choice [{n}]"))),
        }
    }

    /// The event this message stands for.
    pub fn into_event(self) -> SyncEvent {
        match self {
            Self::NewCookie(c) => SyncEvent::NewCookie(c),
            Self::RefreshDelete { cookie, refresh_done } => SyncEvent::RefreshDelete { cookie, refresh_done },
            Self::RefreshPresent { cookie, refresh_done } => SyncEvent::RefreshPresent { cookie, refresh_done },
            Self::SyncIdSet { cookie, refresh_deletes, entry_uuids } => {
                SyncEvent::IdSet { cookie, refresh_deletes, entry_uuids }
            }
        }
    }
}

/// The Sync State Control among `controls`, parsed; `None` if absent or unreadable.
pub(crate) fn find_sync_state(controls: &[Control]) -> Option<SyncStateValue> {
    let c = controls.iter().find(|c| c.oid == OID_SYNC_STATE_CONTROL)?;
    SyncStateValue::parse(c.value.as_deref()?).ok()
}

/// The Sync Done Control among `controls`; the default (no cookie, no deletes) if absent.
pub(crate) fn find_sync_done(controls: &[Control]) -> Result<SyncDoneValue, Asn1Error> {
    match controls.iter().find(|c| c.oid == OID_SYNC_DONE_CONTROL) {
        Some(c) => match &c.value {
            Some(v) => SyncDoneValue::parse(v),
            None => Ok(SyncDoneValue::default()),
        },
        None => Ok(SyncDoneValue::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_A: [u8; 16] = [0xaa; 16];
    const UUID_B: [u8; 16] = [0xbb; 16];

    fn state_value(state: i32, uuid: &[u8], cookie: Option<&[u8]>) -> Vec<u8> {
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.write_enumerated(state);
        enc.write_octet_string(uuid);
        if let Some(c) = cookie {
            enc.write_octet_string(c);
        }
        enc.end_sequence();
        enc.into_bytes()
    }

    #[test]
    fn sync_request_value_matches_the_rfc_asn1() {
        let v = SyncRequest::new(SyncMode::RefreshOnly).encode_value();
        // SEQUENCE { ENUMERATED 1 }: no cookie, reloadHint defaulted.
        assert_eq!(v, [0x30, 0x03, 0x0a, 0x01, 0x01]);
        let v = SyncRequest::new(SyncMode::RefreshAndPersist).with_cookie(b"c1".to_vec()).with_reload_hint(true).encode_value();
        assert_eq!(v, [0x30, 0x0a, 0x0a, 0x01, 0x03, 0x04, 0x02, b'c', b'1', 0x01, 0x01, 0xff]);
        let c = SyncRequest::new(SyncMode::RefreshOnly).to_control();
        assert_eq!((c.oid.as_str(), c.critical), (OID_SYNC_REQUEST_CONTROL, true));
        assert!(!SyncRequest { critical: false, ..SyncRequest::new(SyncMode::RefreshOnly) }.to_control().critical);
    }

    #[test]
    fn sync_state_parses_every_state_with_and_without_a_cookie() {
        for (n, want) in [(0, SyncState::Present), (1, SyncState::Add), (2, SyncState::Modify), (3, SyncState::Delete)] {
            let v = SyncStateValue::parse(&state_value(n, &UUID_A, None)).unwrap();
            assert_eq!((v.state, v.entry_uuid.as_slice(), v.cookie), (want, &UUID_A[..], None));
        }
        let v = SyncStateValue::parse(&state_value(1, &UUID_B, Some(b"csn=7"))).unwrap();
        assert_eq!(v.cookie.as_deref(), Some(&b"csn=7"[..]));
    }

    #[test]
    fn malformed_sync_state_is_rejected() {
        assert!(SyncStateValue::parse(&state_value(9, &UUID_A, None)).is_err(), "unknown state");
        assert!(SyncStateValue::parse(&state_value(1, &[1, 2, 3], None)).is_err(), "short UUID");
        assert!(SyncStateValue::parse(&[]).is_err());
        assert!(SyncStateValue::parse(&[0x04, 0x00]).is_err(), "not a SEQUENCE");
    }

    #[test]
    fn sync_done_defaults_and_fields() {
        // An empty SEQUENCE: no cookie, refreshDeletes FALSE.
        assert_eq!(SyncDoneValue::parse(&[0x30, 0x00]).unwrap(), SyncDoneValue::default());
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.write_octet_string(b"csn=9");
        enc.write_boolean(true);
        enc.end_sequence();
        let v = SyncDoneValue::parse(&enc.into_bytes()).unwrap();
        assert_eq!((v.cookie.as_deref(), v.refresh_deletes), (Some(&b"csn=9"[..]), true));
    }

    fn info_choice(tag: u8, build: impl FnOnce(&mut BerEncoder)) -> Vec<u8> {
        let mut enc = BerEncoder::new();
        enc.begin_context(tag, true);
        build(&mut enc);
        enc.end_context();
        enc.into_bytes()
    }

    #[test]
    fn sync_info_new_cookie() {
        let mut enc = BerEncoder::new();
        enc.write_context(0, b"newcookie");
        assert_eq!(SyncInfo::parse(&enc.into_bytes()).unwrap(), SyncInfo::NewCookie(b"newcookie".to_vec()));
    }

    /// `refreshDone` DEFAULT TRUE: an absent BOOLEAN means the refresh is over.
    #[test]
    fn refresh_delete_and_present_default_to_done_and_read_the_flag() {
        let bare = info_choice(1, |_| {});
        assert_eq!(SyncInfo::parse(&bare).unwrap(), SyncInfo::RefreshDelete { cookie: None, refresh_done: true });
        let present = info_choice(2, |e| {
            e.write_octet_string(b"c");
            e.write_boolean(false);
        });
        assert_eq!(
            SyncInfo::parse(&present).unwrap(),
            SyncInfo::RefreshPresent { cookie: Some(b"c".to_vec()), refresh_done: false }
        );
    }

    #[test]
    fn sync_id_set_collects_uuids_and_defaults_refresh_deletes_to_false() {
        let v = info_choice(3, |e| {
            e.write_octet_string(b"c");
            e.begin_set();
            e.write_octet_string(&UUID_A);
            e.write_octet_string(&UUID_B);
            e.end_set();
        });
        assert_eq!(
            SyncInfo::parse(&v).unwrap(),
            SyncInfo::SyncIdSet { cookie: Some(b"c".to_vec()), refresh_deletes: false, entry_uuids: vec![UUID_A.to_vec(), UUID_B.to_vec()] }
        );
        let deletes = info_choice(3, |e| {
            e.write_boolean(true);
            e.begin_set();
            e.end_set();
        });
        assert_eq!(
            SyncInfo::parse(&deletes).unwrap(),
            SyncInfo::SyncIdSet { cookie: None, refresh_deletes: true, entry_uuids: vec![] },
            "an empty UUID set is legal"
        );
    }

    #[test]
    fn malformed_sync_info_is_rejected() {
        assert!(SyncInfo::parse(&info_choice(7, |_| {})).is_err(), "unknown choice");
        let bad = info_choice(3, |e| {
            e.begin_set();
            e.write_octet_string(&[1, 2, 3]);
            e.end_set();
        });
        assert!(SyncInfo::parse(&bad).is_err(), "short UUID in the set");
        assert!(SyncInfo::parse(&[]).is_err());
    }

    #[test]
    fn controls_are_found_by_oid() {
        let controls = vec![
            Control::new("9.9.9"),
            Control { oid: OID_SYNC_STATE_CONTROL.into(), critical: false, value: Some(state_value(1, &UUID_A, None)) },
            Control { oid: OID_SYNC_DONE_CONTROL.into(), critical: false, value: Some(vec![0x30, 0x00]) },
        ];
        assert_eq!(find_sync_state(&controls).unwrap().state, SyncState::Add);
        assert_eq!(find_sync_done(&controls).unwrap(), SyncDoneValue::default());
        assert!(find_sync_state(&[Control::new("9.9.9")]).is_none());
        assert_eq!(find_sync_done(&[]).unwrap(), SyncDoneValue::default());
    }
}
