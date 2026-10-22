// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCase {
    Handshake,
    Transfer,
    Chacha20,
    Retry,
    Resumption,
    Zerortt,
    Http3,
    Multiconnect,
    V2,
    Ipv6,
    KeyUpdate,
    ConnectionMigration,
    Ecn,
    VersionNegotiation,
}

pub const EXIT_UNSUPPORTED: i32 = 127;

impl TestCase {
    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "handshake" => Some(Self::Handshake),
            "transfer" => Some(Self::Transfer),
            "chacha20" => Some(Self::Chacha20),
            "retry" => Some(Self::Retry),
            "resumption" => Some(Self::Resumption),
            "zerortt" => Some(Self::Zerortt),
            "http3" => Some(Self::Http3),
            "multiconnect" => Some(Self::Multiconnect),
            "v2" => Some(Self::V2),
            "ipv6" => Some(Self::Ipv6),
            "keyupdate" => Some(Self::KeyUpdate),
            "connectionmigration" => Some(Self::ConnectionMigration),
            "ecn" => Some(Self::Ecn),
            "versionnegotiation" => Some(Self::VersionNegotiation),
            _ => None,
        }
    }

    pub fn client_supported(self) -> bool {
        !matches!(
            self,
            Self::ConnectionMigration | Self::Ecn | Self::VersionNegotiation
        )
    }

    pub fn server_supported(self) -> bool {
        !matches!(self, Self::KeyUpdate | Self::Ecn | Self::VersionNegotiation)
    }
}
