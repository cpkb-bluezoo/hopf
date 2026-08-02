// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! gRPC Content-Type codec negotiation (`application/grpc[+format]`).

/// Payload encoding negotiated via the gRPC `Content-Type` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcCodec {
    /// `application/grpc` or `application/grpc+proto` — protobuf wire format.
    Proto,
    /// `application/grpc+json` — proto3 JSON mapping inside gRPC frames.
    Json,
}

impl GrpcCodec {
    /// Media type written on responses for this codec.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Proto => "application/grpc",
            Self::Json => "application/grpc+json",
        }
    }
}

/// Parse a gRPC `Content-Type` value into a supported [`GrpcCodec`].
///
/// Accepts optional `;` parameters. Case-insensitive. Returns `None` for
/// unsupported subtypes (`+thrift`, `grpc-web*`, plain JSON, etc.).
pub fn parse_grpc_content_type(ct: &str) -> Option<GrpcCodec> {
    let media = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "application/grpc" | "application/grpc+proto" => Some(GrpcCodec::Proto),
        "application/grpc+json" => Some(GrpcCodec::Json),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_proto_and_json() {
        assert_eq!(parse_grpc_content_type("application/grpc"), Some(GrpcCodec::Proto));
        assert_eq!(
            parse_grpc_content_type("application/grpc+proto"),
            Some(GrpcCodec::Proto)
        );
        assert_eq!(
            parse_grpc_content_type("Application/gRPC+Proto"),
            Some(GrpcCodec::Proto)
        );
        assert_eq!(
            parse_grpc_content_type("application/grpc; charset=utf-8"),
            Some(GrpcCodec::Proto)
        );
        assert_eq!(
            parse_grpc_content_type("application/grpc+proto; charset=utf-8"),
            Some(GrpcCodec::Proto)
        );
        assert_eq!(
            parse_grpc_content_type("  application/grpc  "),
            Some(GrpcCodec::Proto)
        );
        assert_eq!(
            parse_grpc_content_type("application/grpc+json"),
            Some(GrpcCodec::Json)
        );
        assert_eq!(
            parse_grpc_content_type("APPLICATION/GRPC+JSON; charset=utf-8"),
            Some(GrpcCodec::Json)
        );
    }

    #[test]
    fn rejects_unsupported() {
        assert_eq!(parse_grpc_content_type("application/grpc+thrift"), None);
        assert_eq!(parse_grpc_content_type("application/grpc-web"), None);
        assert_eq!(parse_grpc_content_type("application/grpc-web+proto"), None);
        assert_eq!(parse_grpc_content_type("application/json"), None);
        assert_eq!(parse_grpc_content_type(""), None);
        assert_eq!(parse_grpc_content_type("text/plain"), None);
    }
}
