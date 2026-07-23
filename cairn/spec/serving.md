---
cairn: spec
capability: serving
status: current
---

# Serving Topology and Fronts

Carillon ships as one core (watcher supervisor, delivery, metering, store) behind a REST + SSE API, deployed in one of three fronts that differ only in serving topology, never in code paths. The reference UI (`carillon-frontend`) is a separate repo and a pure client of this API. A deployment either runs headless (localhost API plus admin token), serves the UI from the same origin as the API, or splits the API from a cross-origin CDN front. The `[api]` config block selects the front. Credential handling and route scoping live in [[auth]]; this capability covers where things are served and the config that shapes it.

### Requirement: Headless self-host front
Carillon SHALL support a headless front where the daemon and its API listen on localhost only and no UI is served. Watches are managed through the control API driven by the admin token (`api.admin_token`), or bulk-populated by the bundled `carillon-backend import`, which writes the store directly and needs no token. Operators SHALL bind to localhost and front it with their own auth/proxy if exposed, because the process holds every credential and can redirect every webhook.

### Requirement: Self-host with the UI front
Carillon SHALL support serving the reference dashboard from the same origin as the API by pointing `ui_dir` at a built `carillon-frontend` `dist/`. Being same-origin, this front SHALL require no CORS and SHALL pair with a local token. API routes SHALL take precedence over the static files; unknown paths SHALL fall back to the SPA entrypoint.

#### Scenario: A request path matches both a static file and an API route
- **GIVEN** `ui_dir` is set and the daemon is serving both the SPA and the API
- **WHEN** a request arrives for an API route path (e.g. `/watches`, `/events`)
- **THEN** the API route handles it, and only otherwise-unknown paths fall back to the SPA entrypoint

### Requirement: SaaS front
Carillon SHALL support a SaaS front where the API box serves only JSON and the `carillon-frontend` `dist/` is served from a CDN, cross-origin. This front SHALL set `cors_allow_origin` to the front's origin so the browser can call the API. Because the capability link travels as an `Authorization: Bearer` header (see [[auth]]), cross-origin access needs only a preflight plus this allow-list, with no cookies, SameSite, or CSRF; TLS SHALL be terminated at a reverse proxy in front.

### Requirement: Config surface selects the front
The `[api]` block SHALL expose `ui_dir` (serve a built UI at the origin, enabling the self-host-with-UI front), `cors_allow_origin` (allow a cross-origin front to call the API, enabling the SaaS front), `admin_token` (the unscoped fleet-wide bearer for ops / headless, see [[auth]]), and `public_url` (the externally reachable base URL). These toggles over one core SHALL select the front without changing code paths.

### Requirement: Endpoints at a glance
Carillon SHALL expose, over REST + SSE: `GET /` (service metadata, or the UI when `ui_dir` is set), `GET /health` (liveness), `GET /openapi.yaml` (the API contract), `POST /test` (read-only credential probe, rate-limited), the `/watches` routes (watch CRUD, pause/resume, rotate-secret), `GET /deliveries` (delivery log), the `/accounts` routes, and `GET /events` (SSE live stream). Route-level authentication and scoping are defined in [[auth]]; entitlement in [[billing]].
