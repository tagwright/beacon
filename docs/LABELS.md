# beacon labels

beacon discovers containers by label. A container opts in with `beacon.enable`,
and the other labels tune what beacon does with it. A label names intent and
nothing else. It never carries a URL, a token, or an endpoint, because container
labels are readable by anything that can reach the socket. The channel a label
names is resolved against the `channels` table in beacon's config.

## Namespaces

The primary namespace is `beacon.*`. The portable alias `tagwright.notify.*` is
accepted for every key, so `beacon.channel` and `tagwright.notify.channel` mean
the same thing. Setting one key under both prefixes with different values is a
validation error.

## Keys

Every key is optional except `beacon.enable`.

| label | value | default |
| --- | --- | --- |
| `beacon.enable` | Opt in. Truthy values are `true`, `1`, `yes`, `on` (case-insensitive). Anything else is off. | off |
| `beacon.channel` | The channel to route this container's alerts to, resolved against the `channels` table in config. | the operator-level watch default channel |
| `beacon.on` | Comma-separated events that raise an alert (see the event list below). | the default event set |
| `beacon.exclude` | Comma-separated events to drop from `beacon.on`, or from the default set when `beacon.on` is unset. | none |
| `beacon.min-interval` | A per-container floor between delivered alerts, as a Go duration (`30s`, `5m`, `1h`). The first alert fires, repeats inside the window are digested. | no floor |
| `beacon.name` | The name shown for the container in the alert. | the container name |
| `beacon.severity` | A severity tag routing can match on (see below). It is an enrichment tag and a match input, not a level override, and it never changes the alert's courier level. Any string you choose. | none |

## Events

The events beacon raises from the container runtime:

| event | raised when |
| --- | --- |
| `die` | the container exits |
| `oom` | the container is OOM-killed |
| `health_status` | the container's healthcheck transitions (unhealthy raises an alert, healthy raises a recovery) |
| `restart` | the container's restart cadence crosses beacon's restart-loop threshold |

With `beacon.on` unset, a container opted in gets all four: `die`, `oom`,
`health_status`, `restart`.

## Example

```yaml
services:
  api:
    image: example/api
    labels:
      beacon.enable: "true"
      beacon.channel: "ops"
      beacon.on: "die,health_status,restart"
      beacon.min-interval: "5m"
      beacon.name: "API service"
```

## Labels as routing match inputs

A routing rule matches on a container's raw labels, not only on beacon's own
keys. Any label the container carries is available to a rule:

```yaml
rulesets:
  fleet:
    rules:
      - match: { labels: { env: prod, tier: db } }
        to: dba-oncall
    default: ops
```

Label matching is exact and case-sensitive. Every key in a rule's `labels:` map
must be present with the given value, and they are ANDed, so an absent key is a
non-match. `beacon.severity` is the one exception: it is matched through the
dedicated `severity:` dimension (`match: { severity: critical }`), not through
`labels:`.

## Recreate to adopt

A running container does not pick up new labels. After adding beacon labels,
recreate the container with its own compose project so beacon sees them on the
next socket event.
