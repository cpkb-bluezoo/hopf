# hopf-mailbox

IMAP-level mailbox storage for Hopf (Gumdrop `org.bluezoo.gumdrop.mailbox` port).

## Backends

- **mbox** — single-file mailbox with a `.flags` sidecar for IMAP system flags and keywords
- **Maildir++** — hierarchical folders with `.uidlist` / `.keywords`, including **COPY** and **MOVE**

## Indexing

Search indexes (`.gidx`) store headers, flags, sizes, and dates. **Body text is not indexed by default** (disk-conscious). Enable with [`IndexConfig::body_indexing`](crate::IndexConfig).

`TEXT` / `BODY` searches use the body index when enabled; otherwise they fall back to parsing message content.

## Storage pool

Indexing and searching are blocking filesystem work. Call [`Mailbox`](crate::Mailbox) `search` / index rebuild only from the Runtime [`StorageExecutor`](hopf_core::StorageExecutor) (see [`pool`](crate::pool)), never on a reactor thread.
