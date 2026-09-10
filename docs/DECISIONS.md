# beacon decisions record

The concrete design calls this Stage 1 froze, and the points still open for the
arbiter. It records what the skeleton implements and why, so a later stage
fills the seams without relitigating the shape. The charter governs; where this
record and the charter disagree, the charter wins and this record is wrong.

## Language and Go version

beacon is Go, the suite default. It builds on **Go 1.25**, not 1.23.

This is a deviation from the Stage 1 brief, which asked for go 1.23. It is
forced, not chosen: beacon imports `github.com/tagwright/core`, whose `go.mod`
declares `go 1.25.0` because the Docker SDK's transitive dependency chain
requires it (the Playbook's own gotcha). A go 1.23 module cannot compile a
dependency that declares 1.25, so beacon on 1.23 does not build at all. courier
alone would run on 1.23, but the shared runtime abstraction sets the floor. The
build container is therefore `golang:1.25`, not `golang:1.23`.

## Label grammar

beacon discovers containers by label through core, the same opt-in model the
rest of the suite uses.

- **Primary namespace `beacon.*`, portable alias `tagwright.notify.*`.** This
  follows the established suite pattern exactly (aboard is `aboard.*` plus
  `tagwright.auth.*`). Setting the same key under both prefixes with different
  values is a validation error.

  This reconciles the Stage 1 brief, which named the grammar `notify.*`. A bare
  `notify.*` prefix would break the one-namespace-per-tool convention every
  coverage scan keys off, and it collides with any other tool that might want a
  "notify" verb. Carrying the intent in the alias (`tagwright.notify.*`) keeps
  the readable verb while staying inside the convention. **Open for the
  arbiter:** confirm `beacon.*` + `tagwright.notify.*`, or override to a bare
  `notify.*`.

The keys, all optional except enable:

| label | meaning | default |
| --- | --- | --- |
| `beacon.enable` | opt-in, truthy (`true`/`1`/`yes`/`on`) | off |
| `beacon.channel` | operator-named channel to route this container's alerts to | operator-level watch default |
| `beacon.on` | comma-separated event set that raises an alert | the default event set below |
| `beacon.exclude` | comma-separated events to drop from `on` (or the default set) | none |
| `beacon.min-interval` | minimum time between delivered alerts for this container (Go duration, e.g. `5m`) | no floor |
| `beacon.name` | human-friendly container name shown in the alert | the container name |

- **Default event set: `die`, `oom`, `health_status`, `restart`.** A container
  that opts in without naming `beacon.on` gets these. They are the lifecycle
  and health events the charter names (exit or die, OOM-kill, a healthcheck
  going unhealthy, a restart loop).
- A label names intent only. It never carries a URL, a token, or an endpoint.
  The channel is a name resolved against beacon's config.

## The core watch gap (RESOLVED in Stage 3 via core v0.6.0, Option A)

**Resolved.** Option A below was taken: core v0.6.0 added the oom and
health_status event types and the exit-code/oom/restart inspect fields, and
beacon's watch path now consumes them (see "The watch path is complete" below).
The original decision record is kept here for history.

**This was the one charter point not implementable against the Stage 1
dependencies, and it needed an arbiter decision before the watch path could meet
its charter.**

The charter's watch scope is: raise an alert on exit or die, OOM-kill, a
healthcheck going unhealthy, and a restart loop. core v0.5.0's `Watch` emits
only `start`, `stop`, `die`, and `destroy`; its `Event` carries no exit code,
no OOM flag, and no restart count; and its `Inspect` exposes a health status
string but not the exit code, OOM flag, or restart count either. So of beacon's
default event set, only **container die** is raisable through core today. `oom`,
`health_status`, and `restart`, and any exit-code detail, are not reachable.

The suite rule is explicit: if you need a capability core lacks, add it to core
and publish a new tag, rather than reimplementing socket handling locally or
reaching past core to the Docker SDK. So the resolution is a **core change** (a
prospective core v0.6.0) that:

1. Maps the Docker `health_status`, `oom`, and container `restart` event
   actions into new `EventType` values on `Watch`.
2. Surfaces `ExitCode`, `OOMKilled`, and `RestartCount` on the normalized
   `Container` returned by `Inspect` (and ideally an exit code on the die
   `Event` itself).

**Options for the arbiter:**

- **A. Extend core first (recommended).** Sequence a core v0.6.0 with the two
  additions above, then beacon's watch path consumes it. Clean, matches the
  suite rule, and every other watcher benefits. The cost is a core release on
  beacon's critical path.
- **B. Ship beacon watch as die-only now, extend core later.** beacon raises
  die immediately and gains oom/health/restart when core catches up. Gets a
  useful watch path out the door, but it under-delivers the charter's stated
  scope until the core change lands, and the "restart loop" and "unhealthy"
  cases are exactly the ones operators most want.
- **C. beacon reaches the Docker SDK directly for the missing signals.**
  Rejected: it violates the charter boundary ("watches the runtime through
  core") and the suite's no-reimplement rule, and forks socket handling.

Recommendation: **A**, with the beacon skeleton already structured so the new
event kinds are a table addition (`internal/watch/watch.go` maps
`EventType -> kind`), not a rewrite. The grammar already names the full event
set so the label contract does not change when core catches up.

## Ingest wire contract and authentication

One published contract, shared verbatim by beacon's ingest, courier's webhook
channel, and billet's signed webhooks, so no side depends on another's code.

- **Auth: HMAC-SHA256 over the exact request body, header `X-Beacon-Signature`,
  lowercase hex, no prefix.** This is precisely what courier's webhook channel
  already produces (`webhook.go`: `hmac.New(sha256.New, key)` over the marshaled
  body, `hex.EncodeToString`, header `X-Beacon-Signature`). beacon verifies
  exactly what courier signs, which is what "one contract" means. The header
  keeps its `X-Beacon-Signature` name (it is named for beacon) even though the
  library that emits it is now called courier.
- **Authenticated by default.** `auth_mode: hmac` is the default. `auth_mode:
  none` is the explicit opt-in for a closed network, never the default. The
  signing key is a named secret resolved by injection (courier's model), never
  in a label or config value.
- **Payload: courier's webhook shape extended with beacon's routing fields.**
  The base is courier's exact `webhookPayload`:

  ```json
  { "title": "...", "body": "...", "level": "info|warning|error",
    "tags": ["..."], "fields": {"k":"v"}, "timestamp": "RFC3339" }
  ```

  beacon adds three optional fields it governs: `channel` (the operator-named
  channel; omitted means the deployment default), `dedup_key`, and
  `correlation_key`. courier's webhook channel, which does not send these,
  therefore lands on beacon's default channel with a derived dedup key, which is
  the correct behavior for one beacon relaying to another. billet's signed
  webhooks, which control their own body, set them explicitly.
- **Replay guard over the shared field, not a new header.** courier's scheme has
  no replay protection. Rather than fork the contract with a new nonce header,
  beacon rejects a signed request whose `timestamp` is older than a configured
  `max_skew`. This is beacon-side policy over the field the contract already
  carries, so the wire shape stays identical. **Open for the arbiter:** confirm
  the timestamp-skew approach versus a stronger nonce scheme (which would change
  the shared contract for all three implementers).
- **Adapters translate an incoming payload into beacon's native alert** (a
  courier `Notification` plus a channel name and a dedup key). Two ship in Stage
  1: `native` (the payload above) and `gatus` (Gatus's flat
  `{endpoint, group, status, description}` custom-alert webhook, absorbing
  beacon-server's function). Endpoints are `POST /alert/{adapter}` plus
  `GET /health`. Other adapters (Alertmanager) are added on real demand.

## Channel resolution (courier reconciliation)

courier has **no named-channel concept**: `Notify` fans a `Notification` out to
every configured backend whose `MinLevel` the notification meets, addressed by
severity, not by name. beacon's charter needs named channels a label or a POST
selects. So **beacon owns the name-to-channel table** and courier owns delivery:

- beacon's config declares `channels:` keyed by the name labels and POSTs use.
- `internal/delivery` builds **one `courier.Beacon` per named channel**, each
  from that channel's single backend config, and `Deliver(channel, n)` resolves
  the name to its `Beacon` and calls `Notify`.
- An unresolved channel name falls back to the deployment default channel; with
  no default configured it is a delivery error, never a silent drop.

This keeps the boundary the charter draws: beacon governs and routes, courier
delivers, and new channel types are added in courier on real use.

## Alert-policy pipeline

Both ingress paths raise a native `alert.Alert` and hand it to one
`policy.Engine` (`internal/policy`). The pipeline stages, in order:

`normalize -> correlate -> dedup/suppress -> resolve channel -> deliver (spool on failure)`

- **normalize** fills derived fields and guarantees every alert has a dedup key
  and a correlation key.
- **correlate** collapses a watch event and an ingested alert about the same
  container and incident into one alert (a Docker `health_status` and a Gatus
  DOWN for the same service are one incident). Correlation is keyed on the
  container or the service target.
- **dedup and suppress** apply to both ingress paths and follow airlock's storm
  grammar: a window, first occurrence always fires, repeats within the window
  are digested. A crash-looping container and a misbehaving POSTer storm through
  different doors and are floored by the same model.
- **resolve channel** turns the alert's channel name into a `courier.Beacon`
  via the delivery table above.
- **deliver with spool** is the at-least-once handoff below.

Stage 1 implements the stages as seams: normalize and the delivery-with-spool
fallback are wired and tested (including the failure path), while correlate and
dedup/suppress are present as no-op stages to be filled against the frozen
`Alert` shape.

## At-least-once delivery and the spool

Delivery is at-least-once: something reaches a person, or the alert is held for
retry. It is never silently dropped.

- On a delivery failure, beacon retries with bounded backoff. An alert that
  outlives the retry window is written to a **durable disk spool** and replayed
  on recovery. The spool directory must survive a container recreate (a named
  volume in the deploy stack).
- **Replay can produce duplicates**, and that is acceptable: a missed alert is
  the failure a notifier must not have, a duplicate is a tolerable one.
  Duplicates from retry or replay are collapsed by the dedup layer, so
  **dedup-on-replay** is why dedup and the spool are designed together and why
  every alert carries a dedup key before it can be spooled.
- `internal/spool` implements the `Spooler` interface (`Enqueue`, `Replay`,
  `Len`) as a durable disk spool, with bounded in-line backoff in the pipeline
  and replay-on-recovery driven by the daemon. The interface is fault-injectable
  so the at-least-once guarantee is proven on the failure path, which the
  testing standard requires.

## How core and courier plug in

- **core** (`github.com/tagwright/core` v0.5.0): beacon constructs a
  `runtime.Runtime` with `NewDocker` or `NewPodman` and consumes `Watch(ctx)`
  for the watch path, filtering discovery client-side on `Container.Labels`
  (core exposes no label filter). This is subject to the core watch gap above.
  The shared `runtime/runtimetest` fake is what the wiring tests drive.
- **courier** (`github.com/tagwright/courier` v0.2.0): beacon builds
  `courier.Beacon` instances through `courier.New` and delivers with `Notify`.
  courier's `SecretResolver` is beacon's injection point for channel secrets.

Both are public and tagged on GitHub, so a clean-room build fetches them with
`GOPRIVATE=github.com/tagwright/*` and no `replace` directive, which is exactly
what CI and a fresh clone do.

## Independently disableable ingress

Each ingress path has its own `enabled` flag in config, and config validation
requires at least one to be on. A deployment can run watch-only or ingest-only,
per the charter's suite-conformance requirement.

## Stage 2 status (built and green)

Stage 2 made the non-watch core real, everything that does not depend on core's
event richness:

- **Ingest, full.** Native and Gatus adapters, HMAC-SHA256 over the raw body
  (`X-Beacon-Signature`), authenticated by default with the signing key
  resolved by injection, the timestamp-skew replay guard over the contract's
  own timestamp field, and `auth_mode: none` as the explicit closed-network
  opt-in. Accept, reject, and replay-reject are tested.
- **Pipeline, real.** normalize, correlate (coarse, by correlation key), dedup
  and suppress (fine, by dedup key), resolve channel, deliver. The dedup layer
  mirrors airlock's grammar exactly: a window anchored on the last fire, first
  occurrence fires, repeats within the window are digested, dual counters
  feeding both the "N suppressed since the last alert" line on the next fire and
  a periodic per-channel digest, FIFO-capped in-memory state, injectable clock.
  Correlation is beacon's own coarse layer (airlock has none): a first alert
  about an incident holds the floor so a same-incident alert from another source
  collapses into it.
- **Delivery and spool, real, at-least-once.** Bounded in-line retry with
  exponential backoff, a durable disk spool (one atomically written JSON file
  per alert) for what outlives the retry window, a background replayer that
  drains it on recovery, and dedup-on-replay by delivering spooled alerts
  directly (bypassing the storm counter) so a post-outage backlog is not
  mistaken for a storm. The one case an alert is lost, delivery and spooling
  both failing, surfaces as an error rather than a silent success. Proven at the
  run(Deps) seam with fault injection.
- **Config by injection**, plus the operator-level default channel for
  unlabeled containers.

## The watch path is complete (Stage 3, core v0.6.0)

beacon is on core v0.6.0, and the watch path now raises the full `beacon.on`
default set:

- **die** raises from `EventDie`, enriched from Inspect with the exit code and
  the OOM flag.
- **oom** raises from `EventOOM`.
- **health_status** raises from `EventHealthStatusUnhealthy` (Error level) and
  `EventHealthStatusHealthy` (Info, a recovery), since Docker emits an event on
  each transition.
- **restart** is beacon's own policy, not a core event: core reports the raw
  `RestartCount` on Inspect, and beacon's restart detector declares a loop when
  the restart cadence crosses a threshold within a sliding window (config
  `watch.restart_threshold` and `watch.restart_window`, default 3 in 1m). A
  start with `RestartCount == 0` is a fresh start, never a loop; a cooldown of
  one window after a declared loop stops it re-firing on every start, and the
  dedup layer collapses any that slip through.

Enrichment via Inspect is best-effort: a container already gone (a die that
raced the destroy) still raises an alert from what the event carries. Everything
still flows through the one governed pipeline (correlate, dedup, spool).

The Stage 1 read of the v0.5.0 tag was correct: the oom and health_status event
types and the exit-code/oom/restart inspect fields landed in v0.6.0, which is
now published and go-proxy-resolvable.

## Deferred to later stages (seams cut now)

- Periodic digest routing when suppressed alerts spanned channels is per-channel
  today; a cross-channel digest policy is a later refinement.
- Packaging (Dockerfile, deploy stack) and the beacon-server absorption runbook
  are explicitly a later stage. CI (a hosted `ci.yml` gate plus an additive
  self-hosted `ci-selfhosted.yml`) ships in Stage 3.
