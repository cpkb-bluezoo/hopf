# Security Policy

Hopf is a multi-protocol networking framework. We take reports that could
affect confidentiality, integrity, or availability of deployments seriously.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes |
| 0.1.x   | No (historical; please upgrade) |
| main    | Best-effort for unreleased fixes |

Security fixes land on `main` and are released in the next patch or minor
version of the affected crate(s) on [crates.io](https://crates.io/crates/hopf).

## Reporting a Vulnerability

**Please do not open a public GitHub issue** for security vulnerabilities.

### Preferred: GitHub private advisory

Use GitHub’s private vulnerability reporting:

https://github.com/cpkb-bluezoo/hopf/security/advisories/new

That keeps the discussion private until a fix is ready and makes coordinated
disclosure straightforward.

### Email

If you cannot use GitHub advisories, email the maintainer:

- Chris Burdess — dog@gnu.org

Include as much of the following as you can:

- Affected crate(s) and version(s) (e.g. `hopf-smtp 0.2.0`)
- Description of the issue and its impact
- Steps to reproduce (or a minimal proof of concept)
- Whether you are aware of public exploitation
- A contact method and preferred credit name (or request anonymity)

### What to expect

This project is maintained on a volunteer basis. We aim to:

1. **Acknowledge** receipt within **5 working days**
2. **Triage** severity and confirm whether the report is in scope
3. **Fix** or mitigate, and coordinate disclosure with you
4. **Credit** you in release notes / advisory unless you ask otherwise

Please give us a reasonable window to ship a fix before public disclosure.
If a CVE is appropriate, we will help request or assign one as part of the
advisory process.

## Scope

**In scope (examples):**

- Remote code execution, memory safety issues in published crates
- Authentication / authorization bypasses in protocol handlers
- Cryptographic misuse in TLS, QUIC, SASL, DNSSEC, cookies, password stores
- Unsafe defaults that leave a stock service open on the public Internet
  without an explicit opt-in (open relay, unrestricted Origin, unlimited
  message bodies, and similar)
- Path traversal or sandbox escape in FTP / WebDAV / mailbox backends

**Out of scope (examples):**

- Issues that require an already-compromised host or malicious operator
- Denial of service that is inherent to accepting network traffic at scale
  without a disclosed amplification or resource-exhaustion bug in Hopf itself
- Vulnerabilities only present when the application **explicitly disables**
  secure defaults or enables documented demo/insecure options
- Bugs in third-party dependencies (report upstream; tell us if Hopf needs a
  version bump or workaround)
- Social engineering, physical access, or missing best-practice hardening
  outside Hopf’s APIs (firewalling, OS patching, certificate lifecycle)

Example binaries under `examples/` are illustrations, not production
templates; report framework bugs found through them, not “the example binds
plaintext on localhost.”

## Secure defaults

From 0.2.0 onward, stock services prefer fail-closed behaviour for untrusted
peers (no open SMTP relay, QUIC early data off, bounded body/message sizes,
WebSocket Origin allowlists, and related controls). Operators who need
permissive behaviour must opt in deliberately. See the
[HTML reference](https://cpkb-bluezoo.github.io/hopf/) for composition and
protocol docs.

## Thank you

Responsible disclosure helps everyone who runs Hopf. We appreciate researchers
and users who report issues privately and work with us to fix them.
