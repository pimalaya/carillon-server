# Carillon webhooks: payload, signature & verification

Carillon POSTs a small, **content-free** JSON body to your notify URL the instant a watched mailbox changes. This document is the contract: the payload shape, the headers, and how to verify a delivery is genuinely from Carillon and not a spoof or a replay.

> The signature **is** the authentication. Your notify URL is a public endpoint; anyone who learns it can POST to it. Verify every call.

## Payload

```json
{
  "id": "9f2c1e7a4b6d8f0a1c3e5d7b9f0a2c4e",
  "ts": 1784501124,
  "account": "fastmail",
  "event": "new",
  "uid": 111
}
```

- `id`: unique per event, **stable across retries**: dedupe on it.
- `ts`: unix seconds the event was observed (also in the signature).
- `account`: the watch id.
- `event`: `new` · `flags_added` · `flags_removed` · `removed`.
- `uid`: the affected message UID.

There is deliberately **no** sender, subject or body. If you want a rich notification, fetch the envelope yourself with your own credentials after the ping: Carillon never sees it.

## Headers

| Header | Meaning |
|---|---|
| `X-Carillon-Signature` | `t=<ts>,v1=<hex>[,v1=<hex>]`: see below |
| `X-Carillon-Id` | the event `id`, for idempotency |
| `X-Carillon-Event` | the `event` kind |
| `X-Carillon-Account` | the watch id |
| `Content-Type` | `application/json` |

## Signature scheme

Stripe-style. The signed **preimage** is the timestamp, a literal `.`, then the exact raw request body:

```
preimage = "{t}.{raw_body}"
v1       = hex(HMAC_SHA256(secret, preimage))
```

The header carries the timestamp and one or more `v1` values:

```
X-Carillon-Signature: t=1784501124,v1=5257af…,v1=9b31c0…
```

Multiple `v1` values appear **during a secret rotation overlap** (signed with both the new and the previous secret). Accept the delivery if *any* `v1` matches the HMAC computed with the secret you hold.

To verify:

1. Read `t` and the `v1` list from the header.
2. Recompute `expected = hex(HMAC_SHA256(your_secret, t + "." + raw_body))`. Use the **raw** bytes you received; do not re-serialize the JSON.
3. Constant-time compare `expected` against each `v1`; accept on any match.
4. **Replay**: reject if `abs(now - t)` exceeds your tolerance (~5 min).
5. **Idempotency**: we retry failed deliveries, so the same `id` can arrive more than once. Treat a repeated `id` as already handled.
6. Respond `2xx` quickly and process asynchronously.

Carillon only delivers over `https://` (the sole exception is a loopback host, for local sinks and self-host). Non-loopback `http://` notify URLs are refused at watch-creation time.

## Recipes

### Shell (openssl)

```sh
# inputs: $SECRET, the raw body in $BODY, the header value in $SIG
t=$(printf '%s' "$SIG" | sed -n 's/.*t=\([0-9]*\).*/\1/p')
expected=$(printf '%s.%s' "$t" "$BODY" \
  | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.*= //')
printf '%s' "$SIG" | grep -q "v1=$expected" && echo OK || echo BAD
```

### Node.js (Express)

```js
const crypto = require("crypto");

// app.use(express.raw({ type: "application/json" }))  // keep the RAW body
app.post("/carillon", (req, res) => {
  const header = req.get("X-Carillon-Signature") || "";
  const parts = Object.fromEntries(
    header.split(",").map((p) => p.split("=")),
  );
  const t = Number(parts.t);
  if (Math.abs(Date.now() / 1000 - t) > 300) return res.sendStatus(400);

  const expected = crypto
    .createHmac("sha256", process.env.CARILLON_SECRET)
    .update(`${t}.`)
    .update(req.body) // Buffer: the raw body
    .digest("hex");

  const v1s = header.split(",").filter((p) => p.startsWith("v1="));
  const ok = v1s.some((p) =>
    crypto.timingSafeEqual(
      Buffer.from(p.slice(3)),
      Buffer.from(expected),
    ),
  );
  if (!ok) return res.sendStatus(401);

  const event = JSON.parse(req.body.toString());
  // dedupe on event.id, then handle …
  res.sendStatus(200);
});
```

### Python (Flask)

```python
import hashlib, hmac, time
from flask import request, abort

def verify():
    raw = request.get_data()  # raw bytes
    header = request.headers.get("X-Carillon-Signature", "")
    parts = dict(p.split("=", 1) for p in header.split(","))
    t = int(parts.get("t", "0"))
    if abs(time.time() - t) > 300:
        abort(400)

    expected = hmac.new(
        SECRET.encode(), f"{t}.".encode() + raw, hashlib.sha256
    ).hexdigest()
    v1s = [p[3:] for p in header.split(",") if p.startswith("v1=")]
    if not any(hmac.compare_digest(v1, expected) for v1 in v1s):
        abort(401)
```

## Rotating a secret

```sh
curl -X POST http://<carillon>/watches/<id>/rotate-secret \
  -H 'content-type: application/json' -d '{"overlap_secs": 86400}'
# -> { "status": "ok", "secret": "<new>", "prev_expires_at": <unix> }
```

Update your receiver's configured secret to the returned value. Until `prev_expires_at`, deliveries are signed with **both** the old and new secrets (two `v1` values), so a receiver on either secret keeps validating: no dropped events during the cutover. Omit `new_secret` to have Carillon generate one, or pass your own.
