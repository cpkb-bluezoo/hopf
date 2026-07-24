// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Status codes and default reason phrases (RFC 9110 subset).

/// Look up the default reason phrase for a status code.
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_phrases() {
        assert_eq!(reason_phrase(200), "OK");
        assert_eq!(reason_phrase(207), "Multi-Status");
        assert_eq!(reason_phrase(422), "Unprocessable Entity");
        assert_eq!(reason_phrase(423), "Locked");
        assert_eq!(reason_phrase(424), "Failed Dependency");
        assert_eq!(reason_phrase(404), "Not Found");
        assert_eq!(reason_phrase(507), "Insufficient Storage");
        assert_eq!(reason_phrase(999), "Unknown");
    }
}

