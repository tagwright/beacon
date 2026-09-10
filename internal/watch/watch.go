// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package watch is beacon's container-runtime ingress path. It watches the
// runtime through core, and for any container carrying beacon's opt-in labels
// it raises a native alert from lifecycle and health events. Discovery is by
// label, on any container on the host, whether or not it is a tagwright tool.
// beacon watches through core's socket handling rather than reimplementing it.
//
// Stage 1 note on the core watch gap: core's Watch currently emits only
// start/stop/die/destroy and carries no exit code, OOM flag, or restart count,
// and Inspect exposes only a health string. So of beacon's default event set
// (die, oom, health_status, restart) only container die is raisable through
// core today. Raising oom, health_status, and restart, and carrying an exit
// code, needs a core capability that must be added to core and re-tagged
// rather than reimplemented here (see docs/DECISIONS.md). This package maps
// what core surfaces now and leaves the richer kinds for the extended core.
package watch

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/discovery"
	"github.com/tagwright/courier"
	"github.com/tagwright/core/runtime"
)

// eventKinds maps a core EventType to beacon's event-kind vocabulary. Only the
// kinds core surfaces today are present.
var eventKinds = map[runtime.EventType]string{
	runtime.EventDie: "die",
}

// Source is the watch ingress path. It reads core's event stream, parses each
// container's beacon labels, and emits a native alert for the events an opted
// in container asked for.
type Source struct {
	rt             runtime.Runtime
	defaultChannel string
	logger         *slog.Logger
}

// New constructs a watch Source over a core runtime.
func New(rt runtime.Runtime, defaultChannel string, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	return &Source{rt: rt, defaultChannel: defaultChannel, logger: logger}
}

// Run watches the runtime until ctx is cancelled, emitting an alert per
// qualifying event through emit. It returns the watch stream's terminal error,
// or nil on a clean ctx cancellation.
func (s *Source) Run(ctx context.Context, emit func(context.Context, alert.Alert) error) error {
	events, errs := s.rt.Watch(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			if err != nil {
				return fmt.Errorf("beacon: watch stream: %w", err)
			}
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if a, raise := s.alertFor(ev); raise {
				if err := emit(ctx, a); err != nil {
					s.logger.Warn("beacon: watch emit failed", "container", a.Container, "error", err)
				}
			}
		}
	}
}

// alertFor turns a core Event into a native alert, or reports that the event
// should be ignored (unknown kind, not opted in, or not in the container's
// event set).
func (s *Source) alertFor(ev runtime.Event) (alert.Alert, bool) {
	kind, known := eventKinds[ev.Type]
	if !known {
		return alert.Alert{}, false
	}

	spec, err := discovery.Parse(ev.Labels)
	if err != nil {
		s.logger.Warn("beacon: label parse failed", "container", ev.Name, "error", err)
		return alert.Alert{}, false
	}
	if !spec.Enabled || !spec.Wants(kind) {
		return alert.Alert{}, false
	}

	channel := spec.Channel
	if channel == "" {
		channel = s.defaultChannel
	}
	name := spec.Name
	if name == "" {
		name = ev.Name
	}

	return alert.Alert{
		Channel:   channel,
		DedupKey:  ev.ID + "|" + kind,
		Source:    alert.SourceWatch,
		Container: ev.Name,
		Event:     kind,
		Time:      time.Now(),
		Notification: courier.Notification{
			Title: fmt.Sprintf("%s: container %s", kind, name),
			Level: courier.LevelError,
			Fields: map[string]string{
				"container": name,
				"event":     kind,
				"id":        ev.ID,
			},
		},
	}, true
}
