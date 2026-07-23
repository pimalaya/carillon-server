# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added

- Added the IMAP IDLE watcher: one standing connection per watched mailbox, driving the io-imap coroutines over a tokio-rustls stream, folding every change into a canonical content-free event and reconnecting with jittered backoff behind a handshake semaphore.
- Added the delivery worker: content-free, HMAC-SHA256 signed webhooks POSTed per change over a pooled client, with retries, a sqlite delivery log and per-watch secret rotation with overlap.
- Added CardDAV addressbooks as a second source, polling an RFC 6578 sync-collection for changes alongside IMAP.
- Added the axum control API (REST plus an SSE live stream) managing watches at runtime behind capability-link or admin-token bearer auth, described by an embedded OpenAPI contract.
- Added at-rest credential encryption to a per-box age identity, plus OAuth 2.0 watch credentials holding a refresh token and authenticating with OAUTHBEARER.
- Added prepaid-credit metering, magic-link accounts and transactional email, each inert behind a keyless stub until a Stripe or Resend provider is configured.
- Added the SSRF egress guard, the per-IP and per-login rate limiters, and a hardened NixOS service module for production.
