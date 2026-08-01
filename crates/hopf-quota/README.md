# hopf-quota

Per-user storage quota tracking (Gumdrop `org.bluezoo.gumdrop.quota` parity).

Distinct from `hopf_core`'s connection-level traffic tracker: this crate is
about how much storage (and, optionally, how many messages) a *user* has
accumulated — across however many connections or protocols touch their
data. The same `QuotaManager` backs both `hopf-ftp`'s file store and
`hopf-imap`'s RFC 9208 QUOTA extension.

- `Quota` — limits + current usage (storage bytes, message count)
- `QuotaManager` — resolve/check/update by username
- `QuotaPolicy` — named limits (role or default), with human-readable size
  parsing (`"100MB"`, `"10GB"`, `"1TB"`, `"unlimited"`)
- `UnlimitedQuotaManager` / `MemoryQuotaManager` — stock implementations

See [docs/quota.html](../../docs/quota.html).
