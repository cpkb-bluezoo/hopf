# hopf

Umbrella crate for the [Hopf](https://cpkb-bluezoo.github.io/hopf/)
multi-protocol networking framework. Re-exports every `hopf-*` crate as a
module (`hopf::core`, `hopf::http`, `hopf::smtp`, …).

```toml
[dependencies]
hopf = "0.1"   # everything
```

Or pick crates individually:

```toml
[dependencies]
hopf = { version = "0.1", default-features = false, features = ["http", "tls"] }
```

`hopf-core` is always included. Pass-through features: `h3`, `dns-server`,
`dot`, `doq`, `doh`, `dnssec`, `webdav-xattr`.
