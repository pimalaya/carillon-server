---
cairn: change
id: bootstrap
status: landed
created: 2026-07-23
---

# Adopt Cairn and migrate the docs/ folder

## Why
The backend's design lived in a `docs/` folder that mixed current truth with superseded decisions and a running roadmap: the north-star plan, a decisions log with in-place supersessions (e.g. a subscription-billing detour later reverted), a milestone roadmap with a Landed history, per-capability models, and operator runbooks. Cairn keeps these apart — a living spec for current truth, reviewable change proposals, and a dated log for history — so the next reader is not left to reconcile which version won.

## What
Create a `cairn/` root at the repository root. Seed the spec from the current-truth content of the docs as one capability per area (`overview`, `architecture`, `service-model`, `billing`, `webhooks`, `carddav`, `email`, `auth`, `serving`, `hardening`, `production`, `nixos`), folding the operator runbooks in as capabilities too. Fold the roadmap's landed-milestone history and the superseded/reverted decisions into the log. Add the Cairn activation files and the verify hook. Move `openapi.yaml` to the repository root (it is a served contract artifact compiled into the binary, not prose) and repoint its `include_str!` and every reference. Remove the old `docs/` folder and update the README and CONTRIBUTING references.
