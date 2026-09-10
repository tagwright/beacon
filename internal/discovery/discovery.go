// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package discovery parses beacon's opt-in label grammar off a container's
// labels. A label names intent (which events matter, which channel, how to
// tune dedup and suppression); it never carries a URL, a token, or an
// endpoint, because container labels are readable by anything that can reach
// the socket.
//
// The primary namespace is beacon.* and the portable alias is
// tagwright.notify.*, mirroring the suite convention (aboard.* / tagwright.auth.*).
// Setting the same key under both prefixes with different values is a
// validation error.
package discovery

import (
	"fmt"
	"strings"
	"time"
)

const (
	// Prefix is beacon's primary label namespace.
	Prefix = "beacon."
	// AliasPrefix is the portable alias namespace.
	AliasPrefix = "tagwright.notify."
)

// DefaultEvents is the event set a container opts into when it sets
// beacon.enable but does not name beacon.on. These are the lifecycle and
// health events worth alerting on by default.
//
// NOTE (Stage 1): of these, core's Watch currently surfaces only container
// die (mapped from the die event). oom, health_status, and restart require a
// core capability that does not exist yet (see docs/DECISIONS.md, the core
// watch gap). The grammar names the full intended set now so the label
// contract is frozen; the watch path fills them in as core is extended.
var DefaultEvents = []string{"die", "oom", "health_status", "restart"}

// Spec is the parsed per-container beacon configuration.
type Spec struct {
	// Enabled is true when the enable label is truthy.
	Enabled bool
	// Channel is the operator-named channel to route this container's
	// alerts to. Empty means the operator-level default.
	Channel string
	// On is the set of events that raise an alert. Empty means DefaultEvents.
	On []string
	// Exclude is the set of events to drop from On (or from DefaultEvents).
	Exclude []string
	// MinInterval is the minimum time between delivered alerts for this
	// container, following airlock's storm grammar (first fires, repeats
	// within the window are digested). Zero means no per-container floor.
	MinInterval time.Duration
	// Name is a human-friendly name for the container in the alert. Empty
	// falls back to the container name.
	Name string
}

// truthy reports whether a label value is an opt-in truthy value.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// Parse reads beacon's label grammar off a container's labels. It reconciles
// the primary and alias namespaces, erroring when both set the same key to
// different values.
func Parse(labels map[string]string) (Spec, error) {
	get := func(suffix string) (string, error) {
		p, pok := labels[Prefix+suffix]
		a, aok := labels[AliasPrefix+suffix]
		switch {
		case pok && aok && p != a:
			return "", fmt.Errorf("beacon: label %q and alias %q disagree", Prefix+suffix, AliasPrefix+suffix)
		case pok:
			return p, nil
		case aok:
			return a, nil
		default:
			return "", nil
		}
	}

	var spec Spec

	enable, err := get("enable")
	if err != nil {
		return Spec{}, err
	}
	spec.Enabled = truthy(enable)

	if spec.Channel, err = get("channel"); err != nil {
		return Spec{}, err
	}
	on, err := get("on")
	if err != nil {
		return Spec{}, err
	}
	spec.On = splitList(on)
	exclude, err := get("exclude")
	if err != nil {
		return Spec{}, err
	}
	spec.Exclude = splitList(exclude)
	if spec.Name, err = get("name"); err != nil {
		return Spec{}, err
	}

	interval, err := get("min-interval")
	if err != nil {
		return Spec{}, err
	}
	if interval != "" {
		d, perr := time.ParseDuration(interval)
		if perr != nil {
			return Spec{}, fmt.Errorf("beacon: min-interval %q: %w", interval, perr)
		}
		spec.MinInterval = d
	}

	return spec, nil
}

// Events returns the effective event set for a spec: On (or DefaultEvents)
// minus Exclude.
func (s Spec) Events() []string {
	base := s.On
	if len(base) == 0 {
		base = DefaultEvents
	}
	excluded := make(map[string]struct{}, len(s.Exclude))
	for _, e := range s.Exclude {
		excluded[e] = struct{}{}
	}
	out := make([]string, 0, len(base))
	for _, e := range base {
		if _, drop := excluded[e]; !drop {
			out = append(out, e)
		}
	}
	return out
}

// Wants reports whether the spec's effective event set includes the given
// event kind.
func (s Spec) Wants(event string) bool {
	for _, e := range s.Events() {
		if e == event {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
