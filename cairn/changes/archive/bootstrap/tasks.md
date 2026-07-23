---
cairn: tasks
change: bootstrap
---

- [x] Create the cairn/ root with spec/, changes/, log/
- [x] Add the activation files (AGENTS.md, CLAUDE.md, Cursor, Copilot) and the verify hook
- [x] Move openapi.yaml to the repo root; fix the include_str! path and all references
- [x] Seed the design-doc capabilities (overview, architecture, service-model, billing, webhooks, carddav, email)
- [x] Seed the auth and serving capabilities
- [x] Fold the operator runbooks in as capabilities (hardening, production, nixos)
- [x] Fold the roadmap's landed history and the reverted/superseded decisions into the log
- [x] Remove the docs/ folder
- [x] Update README.md and CONTRIBUTING.md references
- [x] cargo check green; cairn verify conformant
