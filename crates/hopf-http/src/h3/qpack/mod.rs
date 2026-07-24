// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QPACK support for HTTP/3 (RFC 9204), initially static-table-only.

mod decode;
mod encode;
mod static_table;

pub use decode::{decode, DecodeError};
pub use encode::encode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_status_200() {
        let block = encode([(":status", "200")]);
        assert_eq!(
            decode(&block).unwrap(),
            vec![(":status".into(), "200".into())]
        );
    }
}
