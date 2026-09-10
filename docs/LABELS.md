# beacon labels

beacon discovers containers by label. A container opts in by setting
`beacon.enable` to a truthy value, and the other labels tune what beacon does.
A label names intent only. It never carries a URL, a token, or an endpoint,
because container labels are readable by anything that can reach the socket. The
channel a label names is resolved against beacon's deployment config.

## Namespaces

The primary namespace is `beacon.*`. The portable alias `tagwright.notify.*` is
accepted for every key. Setting the same key under both prefixes with different
values is a validation error.

## Keys

| label | meaning | default |
| --- | --- | --- |
| `beacon.enable` | Opt in. Truthy values: `true`, `1`, `yes`, `on`. | off |
| `beacon.channel` | The operator-named channel to route this container's alerts to. The name is resolved against the `channels` table in beacon's config. | the operator-level watch default channel |
| `beacon.on` | Comma-separated set of events that raise an alert. | the default event set below |
| `beacon.exclude` | Comma-separated events to drop from `beacon.on` (or from the default set). | none |
| `beacon.min-interval` | Minimum time between delivered alerts for this container, as a Go duration (`30s`, `5m`, `1h`). Follows the suite storm grammar: the first alert fires, repeats inside the window are digested. | no floor |
| `beacon.name` | A human-friendly name for the container shown in the alert. | the container name |

## Events

The event kinds beacon raises from the container runtime:

| event | raised when |
| --- | --- |
| `die` | the container exits |
| `oom` | the container is OOM-killed |
| `health_status` | the container's healthcheck goes unhealthy |
| `restart` | the container enters a restart loop |

The default event set (used when `beacon.on` is unset) is `die`, `oom`,
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

## Recreate to adopt

A running container does not pick up new labels. After adding beacon labels,
recreate the container with its own compose project so beacon sees them on the
next socket event.
