# hopf-ldap

LDAPv3 client and [`CredentialStore`](../hopf-auth) backend for Hopf
(Gumdrop `ldap` / `LDAPRealm` port).

| Module | Role |
|--------|------|
| `asn1` | Definite-length BER codec (ITU-T X.690 subset used by LDAP) |
| `client` | Async LDAPv3 bind / search / unbind on the Hopf Runtime |
| `store` | `LdapCredentialStore` — search-then-bind Realm |

`CredentialStore` stays LDAP-free in `hopf-auth`; this crate plugs in as a
production backend (see issue #124). PAM and other stores remain separate.

See [docs/ldap.html](../../docs/ldap.html) and [docs/auth.html](../../docs/auth.html).
