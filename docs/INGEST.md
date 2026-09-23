# beacon ingest contract

beacon's HTTP ingest path lets any source on the host raise an alert, delivered
by the same governed path as the container-watch path. This is the contract a
signed-webhook source implements. Vikunja is the first external instance, but
the point is general: any HMAC-signing webhook source becomes a beacon source by
declaring an adapter.

## Endpoint

```
POST /alert/<source>
GET  /health
```

`<source>` selects the adapter that translates the request body into one or more
native alerts (`native`, `gatus`, `vikunja`, ...). An unknown source is `404`.

## Authentication, per adapter

Each adapter declares its own authentication, defaulting to the global ingest
settings:

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
      sign_secret: vikunja-webhook   # vikunja's OWN key, distinct from native's
      # signature_header defaults to X-Vikunja-Signature for the vikunja adapter
```

- `auth_mode: hmac` (the default) verifies an HMAC-SHA256 signature over the exact
  request body, lowercase hex, no prefix. An hmac adapter with no key fails
  closed: it rejects every request rather than opening the listener.
- `auth_mode: none` is an explicit opt-in for a closed network.
- The signature header is `X-Beacon-Signature` for `native` and `gatus`, and
  `X-Vikunja-Signature` for `vikunja`. Override it per adapter with
  `signature_header`.
- `sign_secret` names a secret resolved by injection at runtime (from
  `/run/secrets/<name>` or `BEACON_SECRET_<name>`). It is a name, never the key
  itself, and never a plaintext value in config or a label.

The signing scheme is byte-for-byte identical across sources; only the header and
the key differ. A source signs the raw JSON body it POSTs:

```
signature = hex( HMAC_SHA256( key, raw_request_body ) )
```

## Replay guard

When `ingest.max_skew` is set, a signed request whose top-level `timestamp` (or,
for the Vikunja envelope shape, top-level `time`) is older than the skew is
rejected. A payload carrying neither is not replay-guarded.

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

Gatus's flat custom-alert webhook `{endpoint, group, status, description}`. beacon
reports the raw up/down transition and phrases DOWN/RECOVERED itself, so
firing-to-resolved state and the notify-on-resolved policy are beacon's.

### vikunja

Vikunja's signed webhook envelope `{event_name, time, data}`, verified against
`X-Vikunja-Signature` with the vikunja key. Supported events:

| event | data | alerts | level |
| --- | --- | --- | --- |
| `task.reminder.fired` | a single task | one | info |
| `task.overdue` | a single task | one | warning |
| `tasks.overdue` | a list of tasks | one per task | warning each |

Each task's alert carries the task title and identifier (the identifier may be
empty), a dedup key of `vikunja|<task id>`, `event = vikunja`, and the
`event_name` in the notification fields. A due date populates the body when
present; a zero due date leaves it empty.
