# hopf-pop3

POP3 / POP3S server for [Hopf](https://cpkb-bluezoo.github.io/hopf/) (Gumdrop
`pop3` port). Client support is a follow-up.

- **Commands:** USER/PASS, APOP, AUTH (SASL), STAT, LIST, RETR, DELE, RSET,
  TOP, UIDL, CAPA, NOOP, QUIT, STLS, UTF8
- **Auth:** `CredentialStore` + staged handler SPI; default handler opens
  `INBOX` via `MailboxFactory`
- **TLS:** STLS and implicit POP3S
- **Codec:** incremental `ByteStreamLexer` (`KEYWORD [SP TEXT] CRLF`)

```toml
[dependencies]
hopf-pop3 = "0.1"
```

See [docs/pop3.html](https://cpkb-bluezoo.github.io/hopf/pop3.html).
