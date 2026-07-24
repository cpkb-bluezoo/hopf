# hopf-ftp

FTP / FTPS **server** and blocking **client** for Hopf — Gumdrop
`org.bluezoo.gumdrop.ftp` port.

## Server

Control and data connections, PASV via dynamic `Runtime` listeners, stock
`FilesystemFtpHandler` (chrooted root + storage API), and TrustPolicy auth.

## Client

`FtpClient` / `FtpClientBuilder`: USER/PASS, TYPE, path ops, PASV/EPSV
(optional active PORT/EPRT), RETR/STOR/LIST/…, explicit `AUTH TLS` and
implicit FTPS with PROT P data.

RFC 2640 `OPTS UTF8 ON` is wired for inbound pathnames and outbound
replies / listings (ASCII substitution when UTF-8 is off).
