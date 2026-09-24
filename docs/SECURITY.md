<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security

beacon is the single alert path on a host, so the security question is narrow and
sharp: can an alert be forged, and can an alert be silently lost. This document
states what beacon authenticates and what it does not, how it keeps a raised alert
from being dropped, and where the trust boundary actually sits. The claims here
are checkable against the code, against [INGEST.md](INGEST.md), and against the
path-by-path coverage in [TESTING.md](TESTING.md).

## Two ways an alert is raised, two different trust stories

beacon raises alerts from two sources, and they do not share an authentication
model, so it is worth being clear about each.

**The watch path** raises an alert from a container lifecycle or health event: an
exit, an OOM-kill, a healthcheck going unhealthy, a restart loop. beacon learns
these by reading the container runtime through a read-only socket. There is no
signature on a runtime event, because the trust boundary is the socket itself.
Whoever can present events on that socket is the runtime, and anyone who can reach
the socket already controls the host in ways beacon cannot and does not try to
police. beacon takes the socket read-only and treats what the runtime reports as
authoritative.

**The ingest path** is an HTTP endpoint anything on the host can POST an alert to.
This is the path with an authentication story, because it accepts input from
callers beacon does not otherwise trust.

## What the ingest path authenticates

A caller signs the exact request body with HMAC-SHA256 and sends the result as
lowercase hex. beacon recomputes the signature over the raw body it received and
rejects the request if they do not match. The scheme is byte-for-byte identical
across sources, and only the header name and the key differ:

```
signature = hex( HMAC_SHA256( key, raw_request_body ) )
```

Authentication is declared per adapter, which is the part an operator has to get
right on purpose:

- **`auth_mode: hmac` is the default**, and it verifies the signature over the
  exact bytes POSTed. An hmac adapter configured with no key fails closed. It
  rejects every request rather than opening an unauthenticated listener. This is
  the behavior that matters most, and it is pinned by a test
  (`TestHMACNoKeyFailsClosed`).
- **`auth_mode: none` exists, and it is unauthenticated.** It is an explicit
  opt-in for a source on a closed network, and the shipped Gatus adapter uses it
  because Gatus's own webhook cannot HMAC-sign. Anything reachable on the network
  can POST to a `none` adapter. That is the deal you are accepting when you set it,
  and it is why it has to be typed out rather than defaulted.

Each adapter verifies its own header with its own key. The signature tamper matrix
(`TestPerAdapterAuthMatrix`) proves an adapter rejects a request signed for the
wrong header or with the wrong key, so one source's key does not open another
source's endpoint. An unknown source path returns 404.

An optional replay guard rejects a signed request whose timestamp is further from
now than `ingest.max_skew`, in either direction. Be aware of its edge: it reads
the top-level `timestamp` field, or failing that the `time` field, and a payload
that carries neither is not replay-guarded. If replay resistance matters for a
source, that source's payload has to carry a timestamp beacon can read.

## No alert is silently dropped

The other half of the contract is delivery. beacon does not consider an alert done
until the delivery backend confirms it or the alert is safely spooled for retry.
Delivery is at-least-once. On failure beacon retries with bounded backoff, and an
alert that outlives the retry window is written to a disk spool and replayed on
recovery. Replay can produce a duplicate, which the dedup stage collapses. The
tradeoff is deliberate and it points one way: a missed alert is the failure a
notifier must never have, and a duplicate is one it can live with.

The fan-out behavior is the load-bearing case, and it is tested end to end through
the real entrypoint with a fault injected. When one alert routes to two channels
and one channel's delivery fails, only the failed leaf spools and replays, and the
delivered leaf is not re-sent (`TestRunFanOutSpoolsOnlyFailedLeaf`). The history
write happens before the suppression gates, so even a suppressed repeat is
recorded (`TestRunWritesHistoryUnconditionally`).

## Secrets are named, never carried

A label or a POST names a channel. It never carries the channel's URL, token, or
endpoint. Those live in beacon's deployment config and are resolved by injection.
The reason is concrete: a container label is readable by anything that can reach
the container socket, so a secret in a label is a secret published to the host.

`sign_secret` follows the same rule. It is the name of a secret, resolved at
runtime from `/run/secrets/<name>` or the `BEACON_SECRET_<name>` environment
variable. It is never the key itself, and never a plaintext value sitting in the
config file or a label.

## What beacon does not do

beacon reports what happened, and that is the entire surface it exposes to a
compromised caller. It never restarts, stops, rolls back, or execs into a
container. It takes the socket read-only. It is not an inbox, not a destination,
and not an uptime prober. A caller who forges past the ingest authentication, or
who POSTs freely to a `none` adapter, can raise a false alert or a storm of them.
Storm suppression and dedup bound the noise, but the honest statement is that an
unauthenticated adapter trades away forge-resistance for that source, and that is
the operator's choice to make per adapter.

One operational property is a security property in disguise: because beacon sits
in the alert path, beacon's own liveness has to be watched by something that does
not route through beacon. If beacon is down and nothing outside it is watching,
the silence looks exactly like a quiet, healthy host.

## Testing honesty

The pieces above are covered by unit and wiring tests, golden vectors, and the
signature tamper matrix, all present and green. What is not yet in place is the
live end-to-end integration harness that drives the shipped image against a real
socket and a real delivery backend in CI, and the Podman runtime leg is
compile-only. Both are tracked as debt in [TESTING.md](TESTING.md), which reports
coverage path by path. The signing and routing core is proven by golden vectors
and the tamper matrix rather than by a live harness, which is the one gap a
would-be operator should weigh.

## Reporting a vulnerability

Report a suspected vulnerability through GitHub's private vulnerability reporting
on this repository: the **Security** tab, then **Report a vulnerability**. That
keeps the report private to the maintainer while it is triaged.

Please give it a chance to be fixed before disclosing it publicly. Coordinated
disclosure, a fix in hand before the details go public, is what we are asking for,
and it is what protects the people running beacon in their alert path.
