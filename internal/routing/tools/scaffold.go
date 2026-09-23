// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package tools

// scaffoldTemplate is a complete, commented, lint-clean beacon config an
// operator copies and edits. It is a starting point, not a generation wizard:
// every ruleset name and channel here is a placeholder to replace.
const scaffoldTemplate = `# beacon config scaffold.
# Validate an edited copy with: beacon lint --config <this-file>
#
# Routing is fleet-by-default and per-container by exception: fleet-wide policy
# lives in the 'fleet' ruleset below, and a container overrides only by naming a
# beacon.channel. Names are unique across channels and rulesets.

watch:
  enabled: true
  default_channel: fleet      # the fleet default entry (a leaf or a ruleset)

timezone: UTC                 # IANA name; the clock for every time: match
notify_on_resolved: true      # deliver a firing-to-resolved recovery (default on)

spool:
  dir: /var/lib/beacon/spool  # durable, survives a container recreate

# Leaf delivery targets. Each has a courier Type. A ruleset never lives here.
channels:
  ops:
    type: signal
    settings:
      to: "+10000000000"
  oncall:
    type: signal
    settings:
      to: "+10000000000"

# The routing tree. First match wins per ruleset; a match ANDs its dimensions;
# the default is the mandatory terminal catch-all.
rulesets:
  fleet:
    rules:
      - match: { event: oom }             # an OOM kill goes to ops
        to: ops
      - match: { severity: critical }     # a critical container fans out
        to: [ops, oncall]
      - match: { time: "22:00-07:00" }    # quiet hours dedup harder
        to: ops
        repeat_after: 30m
      - match: { state: resolved }        # a recovery routes to the quiet channel
        to: ops
    default: ops                          # REQUIRED terminal
`
