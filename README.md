# beacon

beacon is the single governed alert path on a host. It raises alerts itself from
what the container runtime reports, it accepts alerts anything else raises over
HTTP, and it applies one policy to both (deduplication, storm suppression,
correlation, and routing to a channel the operator named) before handing off to
[courier](https://github.com/tagwright/courier) for delivery. It does not
consider an alert done until courier confirms delivery or the alert is safely
spooled for retry.

The point of a separate tool is not that it decides. A program that POSTs an
alert has already decided. The point is that beacon is the one place where every
alert on a host, however it was raised, goes through one policy, one channel
table, and one delivery guarantee.

> Status: early. The label grammar, the ingest wire contract, and the pipeline
> shape are frozen; the watch mapping, correlation, storm suppression, and the
> durable spool are being filled in against those seams. See `docs/DECISIONS.md`.

## Two ways an alert is raised

**Watch.** beacon watches the container runtime through
[core](https://github.com/tagwright/core) and, for any container carrying its
opt-in labels, raises an alert from lifecycle and health events (exit, OOM-kill,
a healthcheck going unhealthy, a restart loop). Discovery is by label, on any
container on the host. See `docs/LABELS.md`.

**Ingest.** beacon exposes an authenticated HTTP endpoint anything on the host
can raise an alert through, delivered by the same governed path. A caller
presents an HMAC signature over the request body (`X-Beacon-Signature`), the
same contract courier's webhook channel emits, so the two agree without either
depending on the other's code. A first-class Gatus adapter ships; other adapters
are added on demand.

Each path is independently disableable, so a deployment can run watch-only or
ingest-only.

## One governed delivery path

Both paths raise a native alert and hand it to one pipeline:

```
normalize -> correlate -> dedup and suppress -> resolve channel -> deliver
```

- **Correlation** collapses a watch event and an ingested alert about the same
  incident into one alert.
- **Dedup and storm suppression** apply to both paths: a window, the first
  occurrence always fires, repeats are digested.
- **Delivery is at-least-once.** On failure beacon retries with bounded backoff,
  and an alert that outlives the retry window is spooled to disk and replayed on
  recovery. Duplicates are possible on replay and are collapsed by dedup. A
  missed alert is the failure a notifier must not have; a duplicate is a
  tolerable one.

## What beacon is not

beacon reports what happened. It never restarts, stops, rolls back, or execs
into a container, and it takes read-only socket access. It is not an uptime
prober (it reacts to what the runtime reports, it does not poll), not a log
processor, not a destination or an inbox, and not an alert manager with
acknowledgements or on-call schedules. It routes to the channels people already
watch. Delivery itself belongs to courier; new channels are added there.

## Configuration

Channels, endpoints, and secrets live in beacon's deployment config and are
resolved by injection. A label or a POST names a channel; it never carries the
machinery. Because beacon is in the alert path, its own liveness must be watched
by something that does not route through beacon.

## License

GPL-3.0-or-later. See `LICENSE`.
