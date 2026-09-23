# beacon ingest contract

Anything on the host can raise an alert by POSTing it to beacon, delivered by the
same governed path as the container-watch alerts. This is the contract a
signed-webhook source implements. Vikunja is the first external source that ships
with an adapter, but the shape is general: any source that HMAC-signs its webhook
body becomes a beacon source once an adapter maps its payload.

## Endpoints

```
POST /alert/<source>
GET  /health
```

`<source>` selects the adapter that turns the request body into one or more
native alerts (`native`, `gatus`, `vikunja`). An unknown source returns `404`.
`/health` returns `{"ok": true}`.

## Authentication, per adapter

Each adapter declares its own authentication and falls back to the global ingest
settings when it declares none:

```yaml
ingest:
  enabled: true
  auth_mode: hmac            # global default
  sign_secret: beacon-ingest # names the secret that resolves to the global key
  adapters:
    gatus:
      auth_mode: none        # gatus stays unauthenticated on a closed network
    vikunja:
      auth_mode: hmac
      sign_secret: vikunja-webhook   # vikunja's own key, distinct from native's
      # signature_header defaults to X-Vikunja-Signature for the vikunja adapter
```

- `auth_mode: hmac` (the default) verifies an HMAC-SHA256 signature over the exact
  request body. An hmac adapter with no key fails closed: it rejects every request
  rather than opening the listener.
- `auth_mode: none` is an explicit opt-in for a closed network.
- The signature header is `X-Beacon-Signature` for `native` and `gatus`, and
  `X-Vikunja-Signature` for `vikunja`. Override it per adapter with
  `signature_header`.
- `sign_secret` names a secret resolved at runtime, from `/run/secrets/<name>` or
  the `BEACON_SECRET_<name>` environment variable. It is a name, never the key
  itself, and never a plaintext value in config or a label.

The signing scheme is byte-for-byte identical across sources. Only the header and
the key differ. A source signs the raw JSON body it POSTs and sends the result as
lowercase hex, with no prefix:

```
signature = hex( HMAC_SHA256( key, raw_request_body ) )
```

## Replay guard

When `ingest.max_skew` is set, a signed request is rejected if its timestamp is
further from the current time than the skew, in either direction. beacon reads the
top-level `timestamp` field (the native contract) and, failing that, the top-level
`time` field (the Vikunja envelope). A payload that carries neither is not
replay-guarded.

## Adapters

### native

beacon's own payload: courier's webhook shape plus the routing fields beacon
governs.

```json
{
  "title": "...", "body": "...", "level": "info|warning|error",
  "tags": ["..."], "fields": {"k": "v"}, "timestamp": "RFC3339",
  "channel": "ops", "dedup_key": "...", "correlation_key": "..."
}
```

`channel`, `dedup_key`, and `correlation_key` are optional. An omitted `channel`
lands on the ingest fleet default.

### gatus

Gatus's flat custom-alert webhook, `{endpoint, group, status, description}`.
beacon reads the raw up/down transition and phrases DOWN and RECOVERED itself, so
the firing-to-resolved state and the notify-on-resolved policy are beacon's, not
Gatus's.

### vikunja

Vikunja's signed webhook envelope, `{event_name, time, data}`, verified against
`X-Vikunja-Signature` with the vikunja key. Supported events:

| event | data | alerts | level |
| --- | --- | --- | --- |
| `task.reminder.fired` | one task | one | info |
| `task.overdue` | one task | one | warning |
| `tasks.overdue` | a list of tasks | one per task | warning each |

Each task's alert carries the task title and identifier (the identifier can be
empty), a dedup key of `vikunja|<task id>`, `event = vikunja`, and the
`event_name` in the notification fields. A due date fills the alert body when the
task has one, and leaves it empty when it does not. An event beacon does not
recognize yields no alerts and no error, so subscribing beacon to more Vikunja
events than it maps is harmless.
