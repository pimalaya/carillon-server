# 🔔 Carillon backend [![Matrix](https://img.shields.io/badge/chat-%23pimalaya-blue?style=flat&logo=matrix&logoColor=white)](https://matrix.to/#/#pimalaya:matrix.org) [![Mastodon](https://img.shields.io/badge/news-%40pimalaya-blue?style=flat&logo=mastodon&logoColor=white)](https://fosstodon.org/@pimalaya)

Watch server holding IMAP IDLE and emitting content-free webhooks

Carillon signals; it never syncs. It emits that something changed on a remote mailbox and which UID, never the sender, subject or body. The consumer, which holds the credentials, enriches the notification itself.

## Table of contents

- [Features](#features)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Nix](#nix)
  - [Sources](#sources)
- [Configuration](#configuration)
- [Usage](#usage)
- [License](#license)
- [AI disclosure](#ai-disclosure)
- [Contributing](CONTRIBUTING.md)
- [Social](#social)
- [Sponsoring](#sponsoring)

## Features

- Holds one standing IMAP IDLE connection per watched mailbox on a single box, folding every change into a canonical content-free event
- Emits an HMAC-SHA256 signed webhook per change, decoupled from the watch loop, with retries, a delivery log and per-watch secret rotation
- Watches CardDAV addressbooks too, polling the collection for changes alongside IMAP
- Keeps a strictly read-only posture: mailboxes are opened for examination only and no write command is ever issued
- Encrypts credentials at rest to a per-box age key, and authenticates watches by password or by OAuth 2.0 refresh token
- Exposes a REST and SSE control API to manage watches at runtime, described by an embedded OpenAPI contract
- Guards outbound connections against SSRF, rate-limits the unauthenticated probes and ships a hardened NixOS module for production
- Meters usage as prepaid credits behind magic-link accounts and transactional email, all inert until a provider is configured

## Installation

### Cargo

```sh
cargo install --locked --git https://github.com/pimalaya/carillon-backend.git
```

### Nix

With the [Flakes](https://nixos.wiki/wiki/Flakes) feature enabled:

```sh
nix profile install github:pimalaya/carillon-backend
```

Or run without installing:

```sh
nix run github:pimalaya/carillon-backend
```

### Sources

```sh
git clone https://github.com/pimalaya/carillon-backend
cd carillon-backend
nix run
```

## Configuration

The configuration is infrastructure only: the sqlite store, the age key and a few tuning knobs. Watches do not live here; they enter the store through the control API or the `import` subcommand. The daemon loads the config from the first of an explicit path argument, the `CARILLON_CONFIG` environment variable, or carillon.toml in the working directory. A documented sample lives at [carillon.sample.toml](./carillon.sample.toml), and the bulk-import format at [accounts.sample.toml](./accounts.sample.toml).

## Usage

Run `carillon-backend --help` for the two subcommands: `serve` runs the daemon, `import` bulk-loads watches into the store. The control API is described by the OpenAPI contract at [openapi.yaml](./openapi.yaml); the design spec, serving fronts, webhook payload and production runbook live in the [cairn](./cairn) folder, which follows the [Cairn](https://github.com/pimalaya/cairn) convention (`spec/` current design, `changes/` proposals, `log/` history).

## License

This project is licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## AI disclosure

This project is developed with AI assistance. This section documents how, so users and downstream packagers can make informed decisions.

- **Tools**: Claude Code (Anthropic), Opus 4.8, invoked locally with a persistent project-scoped memory and a small set of repo-specific rules.
- **Used for**: Refactors, mechanical multi-file edits, boilerplate (feature gates, error enums, derive macros, trait impls), test scaffolding, doc polish, exploratory design conversations.
- **Not used for**: Engineering, critical code, git manipulation (commit, merge, rebase…), real-world tests.
- **Verification**: Every AI-assisted change is read, compiled, tested, and formatted before commit (`nix develop --command cargo check / cargo test / cargo fmt`). Behavioural correctness is verified against the relevant RFC or upstream spec, not assumed from the model output. Tests are never adjusted to fit AI-generated code; the code is adjusted to fit correct behaviour.
- **Limitations**: AI models occasionally produce code that compiles and passes tests but is subtly wrong: off-by-one errors, missed edge cases, plausible but nonexistent APIs, stale RFC references. The verification workflow catches most of this; it does not catch all of it. Bug reports are welcome and taken seriously.
- **Last reviewed**: 23/07/2026

## Social

- Chat on [Matrix](https://matrix.to/#/#pimalaya:matrix.org)
- News on [Mastodon](https://fosstodon.org/@pimalaya) or [RSS](https://fosstodon.org/@pimalaya.rss)
- Mail at [pimalaya.org@posteo.net](mailto:pimalaya.org@posteo.net)

## Sponsoring

[![nlnet](https://nlnet.nl/logo/banner-160x60.png)](https://nlnet.nl/)

Special thanks to the [NLnet foundation](https://nlnet.nl/) and the [European Commission](https://www.ngi.eu/) that have been financially supporting the project for years:

- 2022 → 2023: [NGI Assure](https://nlnet.nl/project/Himalaya/)
- 2023 → 2024: [NGI Zero Entrust](https://nlnet.nl/project/Pimalaya/)
- 2024 → 2026: [NGI Zero Core](https://nlnet.nl/project/Pimalaya-PIM/)
- *2027 in preparation…*

If you appreciate the project, feel free to donate using one of the following providers:

[![GitHub](https://img.shields.io/badge/-GitHub%20Sponsors-fafbfc?logo=GitHub%20Sponsors)](https://github.com/sponsors/soywod)
[![Ko-fi](https://img.shields.io/badge/-Ko--fi-ff5e5a?logo=Ko-fi&logoColor=ffffff)](https://ko-fi.com/soywod)
[![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-ffdd00?logo=Buy%20Me%20A%20Coffee&logoColor=000000)](https://www.buymeacoffee.com/soywod)
[![Liberapay](https://img.shields.io/badge/-Liberapay-f6c915?logo=Liberapay&logoColor=222222)](https://liberapay.com/soywod)
[![PayPal](https://img.shields.io/badge/-PayPal-0079c1?logo=PayPal&logoColor=ffffff)](https://www.paypal.com/paypalme/soywod)
