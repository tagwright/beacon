// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package alert defines beacon's native alert, the single internal shape both
// ingress paths (watch and ingest) produce and the one the policy engine
// consumes. It is courier's Notification plus the routing and identity fields
// beacon governs: the named channel to deliver to, the dedup key that
// collapses repeats, and the correlation key that collapses a watch event and
// an ingested alert about the same incident into one.
package alert

import (
	"time"

	"github.com/tagwright/courier"
)

// Source names which ingress path raised an alert.
type Source string

const (
	// SourceWatch is the container-runtime watch path (via core).
	SourceWatch Source = "watch"
	// SourceIngest is the authenticated HTTP ingest path.
	SourceIngest Source = "ingest"
)

// Alert is beacon's native alert. Both ingress paths normalize to this shape
// and hand it to the policy engine, which routes it to courier for delivery.
type Alert struct {
	// Channel is the operator-named channel to deliver through. It is
	// resolved against beacon's config, never carrying the destination
	// itself. Empty means the deployment default channel.
	Channel string

	// DedupKey identifies repeats of the same alert for suppression on
	// retry, replay, or a storm. Two alerts with the same key are the same
	// alert.
	DedupKey string

	// CorrelationKey groups alerts about one incident from different
	// sources (a watch health_status and an ingested Gatus DOWN for the
	// same service) so they collapse into one delivered alert.
	CorrelationKey string

	// Source is which ingress path raised this alert.
	Source Source

	// Adapter names the ingest adapter that produced the alert on the
	// ingest path ("native", "gatus", ...). Empty on the watch path.
	Adapter string

	// Container is the container name or id when the alert is about a
	// specific container, used for correlation. Empty otherwise.
	Container string

	// Event is the event kind that raised the alert ("die", "oom",
	// "health_status", "restart", "gatus", ...).
	Event string

	// MinInterval is a per-alert dedup-window floor, set from a container's
	// beacon.min-interval label. Zero means use the deployment default
	// dedup window.
	MinInterval time.Duration

	// Notification is the payload courier will deliver.
	Notification courier.Notification

	// Time is when beacon raised the alert.
	Time time.Time
}
