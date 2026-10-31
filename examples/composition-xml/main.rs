// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Composition XML example (see docs/composition.html).
//!
//! Loads `composition.xml` from disk: two named handlers resolved through a
//! `CompositionRegistry`, an `<allow>`/`<rate-limit>`-guarded listener, and a
//! `<dial-tcp>` peer that fires as soon as the composition starts.
//!
//! ```text
//! cargo run -p composition-xml
//! # other terminal:
//! nc 127.0.0.1 8090   # echo
//! nc 127.0.0.1 8091   # shout (uppercases input)
//! ```

use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use hopf_core::{LoopBuf, Composition, CompositionRegistry, Endpoint, ProtocolHandler};

struct Echo;

impl ProtocolHandler for Echo {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        let (first, second) = buf.readable_spans();
        endpoint.send(first);
        endpoint.send(second);
        buf.advance(buf.len());
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}

struct Shout;

impl ProtocolHandler for Shout {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        let (first, second) = buf.readable_spans();
        endpoint.send(&first.to_ascii_uppercase());
        endpoint.send(&second.to_ascii_uppercase());
        buf.advance(buf.len());
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}

/// Dials the echo listener as soon as the composition starts (`<dial-tcp>`),
/// sends a greeting, prints whatever comes back, then closes.
struct DialGreet;

impl ProtocolHandler for DialGreet {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        endpoint.send(b"hello from dial-tcp");
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        let (first, second) = buf.readable_spans();
        let _ = writeln!(
            io::stderr(),
            "dial-tcp got back: {}{}",
            String::from_utf8_lossy(first),
            String::from_utf8_lossy(second)
        );
        buf.advance(buf.len());
        endpoint.close();
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
}

fn main() -> io::Result<()> {
    let mut registry = CompositionRegistry::new();
    registry.register(
        "echo",
        Arc::new(|| Box::new(Echo) as Box<dyn ProtocolHandler>),
    );
    registry.register(
        "shout",
        Arc::new(|| Box::new(Shout) as Box<dyn ProtocolHandler>),
    );
    registry.register(
        "dial-greet",
        Arc::new(|| Box::new(DialGreet) as Box<dyn ProtocolHandler>),
    );

    let xml_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("composition.xml");
    let comp = Composition::from_xml_path(&xml_path, &registry)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    eprintln!("loaded {}", xml_path.display());
    for addr in &comp.listen_addrs {
        eprintln!("listening on {addr}");
    }
    eprintln!("(dial-tcp already fired against the echo listener; see stderr above)");
    eprintln!("try: nc 127.0.0.1 8090 (echo)   nc 127.0.0.1 8091 (shout)");
    eprintln!("press Enter to stop");

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    comp.shutdown();
    Ok(())
}
