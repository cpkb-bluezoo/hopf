# hopf-auth

TrustPolicy, IdentityMaterial, credential stores, and **SASL mechanisms**
(Gumdrop parity, excluding GSSAPI):

| Mechanism | RFC / notes |
|-----------|-------------|
| PLAIN | RFC 4616 |
| LOGIN | legacy two-step |
| CRAM-MD5 | RFC 2195 |
| DIGEST-MD5 | RFC 2831 (deprecated; kept for parity) |
| SCRAM-SHA-256 | RFC 5802 / 7677 |
| OAUTHBEARER | RFC 7628 |
| EXTERNAL | RFC 4422 App. A |

HTTP Digest helpers live in [`http_digest`](src/http_digest.rs); HTTP Basic /
Digest / Bearer consumers are in `hopf-http`.

See [docs/auth.html](../../docs/auth.html).
