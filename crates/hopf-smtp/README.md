# hopf-smtp

SMTP / SMTPS **server** and blocking **client** for Hopf — Gumdrop
`org.bluezoo.gumdrop.smtp` port.

Protocol engine, staged connection-handler SPI, STARTTLS / AUTH PLAIN,
DATA (dot-stuffing) and BDAT. Stock handler accepts and discards mail.

## Relay

`SimpleRelayService` / `SimpleRelayHandler` — open MX relay using
`hopf-dns` and `SmtpClient` (dev/test only; not for untrusted networks).
Local mailbox delivery remains a follow-up.
