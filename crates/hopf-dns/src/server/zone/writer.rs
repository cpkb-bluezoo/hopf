// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Zone file serialisation: the inverse of [`loader`](super::loader).

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use super::error::ZoneError;
use super::model::Zone;
use super::rdata::{format_rdata, type_mnemonic};

fn absolute(name: &str) -> String {
    format!("{name}.")
}

impl Zone {
    /// Render as a zone file that [`Zone::from_zone_text`] reads back to an
    /// identical zone: SOA first, then owners in name order, every name
    /// absolute.
    pub fn to_zone_text(&self) -> String {
        let mut out = format!("$ORIGIN {}\n$TTL {}\n", absolute(self.origin()), self.default_ttl());
        for rr in self.records() {
            out.push_str(&format!(
                "{} {} IN {} {}\n",
                absolute(&rr.name),
                rr.ttl,
                type_mnemonic(rr.raw_type),
                format_rdata(rr.raw_type, &rr.rdata)
            ));
        }
        out
    }

    /// Write the zone file atomically: to a sibling temporary file, synced,
    /// then renamed over `path`, so a crash never leaves a torn zone file.
    /// Blocking; call from a storage worker.
    pub fn write_zone_file(&self, path: &Path) -> Result<(), ZoneError> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let result = (|| -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(self.to_zone_text().as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(|e| ZoneError::new(format!("{}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_written_zone_loads_back_identically() {
        let z = Zone::from_zone_text(
            "$ORIGIN example.com.\n$TTL 300\n@ SOA ns1 hm 7 3600 900 604800 60\n NS ns1\nns1 A 192.0.2.1\n\
             t TXT \"a \\\"q\\\" \\\\ b\" \"\\001\"\nx TYPE999 \\# 3 aabbcc\nm MX 5 mail\n*.w CNAME ns1\n",
            None,
        )
        .unwrap();
        let text = z.to_zone_text();
        let back = Zone::from_zone_text(&text, None).unwrap();
        assert_eq!(back.records(), z.records(), "{text}");
        assert_eq!(back.default_ttl(), 300);
    }

    #[test]
    fn write_zone_file_is_atomic_and_readable() {
        let dir = std::env::temp_dir().join(format!("hopf-zone-w-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("z.zone");
        let z = Zone::from_zone_text("$ORIGIN e.org.\n@ 60 SOA n h 1 2 3 4 5\n", None).unwrap();
        z.write_zone_file(&path).unwrap();
        assert!(!dir.join("z.zone.tmp").exists());
        assert_eq!(Zone::from_zone_file(&path, None).unwrap().records(), z.records());
        let _ = std::fs::remove_dir_all(dir);
    }
}
