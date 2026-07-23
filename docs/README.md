# docs/

Development memory of the repository: architecture and design notes, plans and their outcomes. One line per file below; plans are never deleted once done, their Landed sections are the history.

- [CARILLON_PLAN.md](./CARILLON_PLAN.md): the original north-star vision, scope, cost model and business shape.
- [DECISIONS.md](./DECISIONS.md): the product and design decisions refined since the plan.
- [ROADMAP.md](./ROADMAP.md): the action plan from prototype to shippable product.
- [SERVICE_MODEL.md](./SERVICE_MODEL.md): the account, PIM account and service hierarchy with its onboarding flow.
- [BILLING_MODEL.md](./BILLING_MODEL.md): the prepaid-credit billing model and its money invariants.
- [BILLING.md](./BILLING.md): the Stripe setup and sandbox testing guide.
- [EMAIL.md](./EMAIL.md): transactional email deliverability for magic links and notices.
- [WEBHOOKS.md](./WEBHOOKS.md): the delivery payload and its signature verification.
- [CARDDAV.md](./CARDDAV.md): the CardDAV source protocol and its poll engine.
- [SELF_HOST.md](./SELF_HOST.md): the three serving fronts and their configuration.
- [PRODUCTION.md](./PRODUCTION.md): the sequenced go-live runbook for a single VPS.
- [DEPLOY_HARDENING.md](./DEPLOY_HARDENING.md): the blast-radius-ordered production hardening checklist.
- [NIXOS.md](./NIXOS.md): running the daemon on NixOS through the service module.
- [openapi.yaml](./openapi.yaml): the control API contract, served live at /openapi.yaml.
