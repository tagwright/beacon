# beacon

beacon is the single governed alert path on a host. It raises alerts from what
the container runtime reports, accepts alerts anything else raises over HTTP, and
puts both through one policy (deduplication, storm suppression, correlation,
channel routing) before handing off to [courier](https://github.com/tagwright/courier)
for delivery.

A host runs many things that page a human when they break: a container that
exits, a health check that goes red, a scheduled job that fails, an external
monitor that trips. Point each of them at beacon and the dedup window, the storm
floor, the correlation, and the channel table are decided in one place instead
of reimplemented per source. beacon does not consider an alert done until courier
confirms delivery or the alert is safely spooled for retry.

The separate tool is not there to decide. A program that POSTs an alert has
already decided. beacon is there so that every alert on a host, however it was
raised, passes through one policy, one channel table, and one delivery guarantee.
It is the same shape as Traefik or Homepage: a daemon that watches the container
socket and drives a proven backend, configured by labels, rather than one more
thing to babysit.

## Quickstart

beacon's routing tools run without a socket or a delivery backend, so you can
build a config and see exactly where an event would go before deploying anything.

Build the image (`core` and `courier` are fetched as published modules):

```
docker build -t beacon:local .
```

Generate a starter config and validate it. `beacon` is the image entrypoint, so
any subcommand runs as `docker run ... beacon:local <subcommand>`:

```
beacon scaffold > beacon.yml
beacon lint --config beacon.yml
```

```
config loaded and validated
rulesets:
  fleet:
    rule 0 -> ops
    rule 1 -> ops, oncall
    rule 2 -> ops
    rule 3 -> ops
    default -> ops
no lint warnings
```

Trace how an event routes through the config, at the exact time and severity you
give it:

```
beacon explain --config beacon.yml --event oom
```

```
explain: channel="(fleet default)" event="oom" source="watch" severity="" state="firing"
  ruleset "fleet": rule 0 matched -> ops
  leaf "ops"
leaves: ops
```

A critical container fans out to two channels, and `explain` shows the branch it
took to get there:

```
beacon explain --config beacon.yml --event die --severity critical
```

```
explain: channel="(fleet default)" event="die" source="watch" severity="critical" state="firing"
  ruleset "fleet": rule 1 matched -> ops, oncall
  leaf "ops"
  leaf "oncall"
leaves: oncall, ops
```

To run the daemon, give it the container socket read-only, the config, and a
durable spool volume:

```
docker run -d --name beacon \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/beacon.yml:/etc/beacon/beacon.yml:ro" \
  -v beacon-spool:/var/lib/beacon/spool \
  beacon:local
```

A container opts in with labels, and recreates once so beacon sees them:

```yaml
services:
  api:
    image: example/api
    labels:
      beacon.enable: "true"
      beacon.channel: "ops"
      beacon.on: "die,health_status,restart"
```

Two things the scaffold cannot do for you. Its `channels` are `signal`
placeholders, so an alert has nowhere real to land until you point a channel at a
courier backend you actually run. And because beacon sits in the alert path, its
own liveness has to be watched by something that does not route through beacon.

Full label reference: [`docs/LABELS.md`](docs/LABELS.md). Full config keys are
documented on the `Config` type in `internal/config/config.go`.

## Two ways an alert is raised

**Watch.** beacon watches the container runtime through
[core](https://github.com/tagwright/core) and, for any container carrying its
opt-in labels, raises an alert from a lifecycle or health event: an exit, an
OOM-kill, a healthcheck going unhealthy, or a restart loop. Discovery is by
label, on any container on the host. See [`docs/LABELS.md`](docs/LABELS.md).

**Ingest.** beacon exposes an authenticated HTTP endpoint anything on the host
can raise an alert through, delivered by the same path. A caller signs the
request body with HMAC (`X-Beacon-Signature`), the same contract courier's
webhook channel emits, so the two agree without either depending on the other's
code. A Gatus adapter and a Vikunja adapter ship. See
[`docs/INGEST.md`](docs/INGEST.md).

Each path can be turned off on its own, so a deployment can run watch-only or
ingest-only.

## One governed delivery path

Both paths raise a native alert and hand it to one pipeline:

```
normalize -> correlate -> dedup and suppress -> resolve channel -> deliver
```

- **Correlation** collapses a watch event and an ingested alert about the same
  incident into one alert.
- **Dedup and storm suppression** apply to both paths. The first occurrence in a
  window always fires, repeats inside the window are digested.
- **Delivery is at-least-once.** On failure beacon retries with bounded backoff.
  An alert that outlives the retry window is written to a disk spool and replayed
  on recovery. Replay can produce duplicates, which dedup collapses. A missed
  alert is the failure a notifier must not have. A duplicate is one it can live
  with.

## What beacon is not

beacon reports what happened. It never restarts, stops, rolls back, or execs into
a container, and it takes the socket read-only. It is not an uptime prober (it
reacts to what the runtime reports, it does not poll), not a log processor, not a
destination or an inbox, and not an alert manager with acknowledgements or
on-call schedules. It routes to the channels people already watch. Delivery
itself belongs to courier, and new channel types are added there.

## Configuration

Channels, endpoints, and secrets live in beacon's deployment config and are
resolved by injection. A label or a POST names a channel. It never carries the
URL, the token, or the endpoint, because container labels are readable by
anything that can reach the socket.

What the ingest path authenticates, what it does not, and how a raised alert is
kept from being silently dropped are in [`docs/SECURITY.md`](docs/SECURITY.md).

## Status

Early, and versioned at `00.01.00`. The watch path, the HTTP ingest path, and the
full pipeline (correlation, dedup and storm suppression, at-least-once delivery
with a durable spool) are built and covered by unit, wiring, and golden-vector
tests. What is not yet in place is the live end-to-end integration harness that
drives the shipped image against a real socket in CI, and the Podman runtime leg
is compile-only. Both are tracked as debt in
[`docs/TESTING.md`](docs/TESTING.md), which reports coverage honestly, path by
path.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).
