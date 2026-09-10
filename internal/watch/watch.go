// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package watch is beacon's container-runtime ingress path. It watches the
// runtime through core and, for any container carrying beacon's opt-in labels,
// raises an alert from lifecycle and health events: exit or die, OOM-kill, a
// healthcheck transition, and a restart loop. Discovery is by label, on any
// container on the host, whether or not it is a tagwright tool. beacon watches
// through core's socket handling rather than reimplementing it, and it never
// reaches past core to the Docker SDK.
//
// core v0.6.0 surfaces the die, oom, and health_status events directly and
// exposes ExitCode, OOMKilled, and RestartCount on Inspect. Restart-loop
// detection is beacon's own policy over RestartCount and start cadence: core
// reports the raw count, beacon decides what a loop is.
package watch

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/discovery"
	"github.com/tagwright/courier"
	"github.com/tagwright/core/runtime"
)

// Config configures the watch source.
type Config struct {
	// DefaultChannel covers an opted-in container that names no channel.
	DefaultChannel string
	// RestartThreshold and RestartWindow tune restart-loop detection. A
	// threshold of zero disables it.
	RestartThreshold int
	RestartWindow    time.Duration
}

// Source is the watch ingress path. It reads core's event stream, parses each
// container's beacon labels, enriches an alert from Inspect, and emits it into
// the governed pipeline.
type Source struct {
	rt             runtime.Runtime
	defaultChannel string
	restart        *restartDetector
	logger         *slog.Logger
}

// New constructs a watch Source over a core runtime.
func New(rt runtime.Runtime, cfg Config, clk clock.Clock, logger *slog.Logger) *Source {
	if logger == nil {
		logger = slog.Default()
	}
	if clk == nil {
		clk = clock.Real{}
	}
	return &Source{
		rt:             rt,
		defaultChannel: cfg.DefaultChannel,
		restart:        newRestartDetector(clk, cfg.RestartThreshold, cfg.RestartWindow),
		logger:         logger,
	}
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
			s.handle(ctx, ev, emit)
		}
	}
}

// handle processes one event: a start feeds restart-loop detection, a
// die/oom/health event raises an alert directly.
func (s *Source) handle(ctx context.Context, ev runtime.Event, emit func(context.Context, alert.Alert) error) {
	spec, err := discovery.Parse(ev.Labels)
	if err != nil {
		s.logger.Warn("beacon: label parse failed", "container", ev.Name, "error", err)
		return
	}
	if !spec.Enabled {
		return
	}

	if ev.Type == runtime.EventStart {
		s.checkRestartLoop(ctx, ev, spec, emit)
		return
	}

	kind, known := beaconKind(ev.Type)
	if !known || !spec.Wants(kind) {
		return
	}
	a := s.buildAlert(ctx, ev, kind, spec)
	if emitErr := emit(ctx, a); emitErr != nil {
		s.logger.Warn("beacon: watch emit failed", "container", ev.Name, "error", emitErr)
	}
}

// checkRestartLoop consults the detector on a container start and raises a
// restart-loop alert when the cadence crosses the threshold.
func (s *Source) checkRestartLoop(ctx context.Context, ev runtime.Event, spec discovery.Spec, emit func(context.Context, alert.Alert) error) {
	if !spec.Wants("restart") {
		return
	}
	c, err := s.rt.Inspect(ctx, ev.ID)
	if err != nil {
		return
	}
	if !s.restart.observe(ev.ID, c.RestartCount) {
		return
	}
	name := containerName(spec, ev)
	channel := s.channelFor(spec)
	a := alert.Alert{
		Channel:     channel,
		DedupKey:    ev.ID + "|restart",
		Source:      alert.SourceWatch,
		Container:   ev.Name,
		Event:       "restart",
		MinInterval: spec.MinInterval,
		Notification: courier.Notification{
			Title: fmt.Sprintf("restart loop: container %s", name),
			Body:  fmt.Sprintf("container %s has restarted %d times", name, c.RestartCount),
			Level: courier.LevelError,
			Fields: map[string]string{
				"container":     name,
				"event":         "restart",
				"id":            ev.ID,
				"restart_count": strconv.Itoa(c.RestartCount),
			},
		},
	}
	if emitErr := emit(ctx, a); emitErr != nil {
		s.logger.Warn("beacon: restart alert emit failed", "container", ev.Name, "error", emitErr)
	}
}

// buildAlert turns a die/oom/health event into a native alert, enriching the
// content from Inspect on a best-effort basis (a container that is already gone
// still raises an alert from what the event carries).
func (s *Source) buildAlert(ctx context.Context, ev runtime.Event, kind string, spec discovery.Spec) alert.Alert {
	name := containerName(spec, ev)
	recovered := ev.Type == runtime.EventHealthStatusHealthy
	level := courier.LevelError
	if recovered {
		level = courier.LevelInfo
	}

	fields := map[string]string{
		"container": name,
		"event":     kind,
		"id":        ev.ID,
	}
	title := fmt.Sprintf("%s: container %s", kind, name)
	switch {
	case kind == "health_status" && recovered:
		title = fmt.Sprintf("recovered: container %s healthy", name)
	case kind == "health_status":
		title = fmt.Sprintf("unhealthy: container %s", name)
	}

	if c, err := s.rt.Inspect(ctx, ev.ID); err == nil {
		if kind == "die" {
			fields["exit_code"] = strconv.Itoa(c.ExitCode)
			if c.OOMKilled {
				fields["oom_killed"] = "true"
			}
		}
		if kind == "oom" || c.OOMKilled {
			fields["oom_killed"] = "true"
		}
		if c.Health != "" {
			fields["health"] = c.Health
		}
	}

	return alert.Alert{
		Channel:      s.channelFor(spec),
		DedupKey:     ev.ID + "|" + kind,
		Source:       alert.SourceWatch,
		Container:    ev.Name,
		Event:        kind,
		MinInterval:  spec.MinInterval,
		Notification: courier.Notification{Title: title, Level: level, Fields: fields},
	}
}

func (s *Source) channelFor(spec discovery.Spec) string {
	if spec.Channel != "" {
		return spec.Channel
	}
	return s.defaultChannel
}

func containerName(spec discovery.Spec, ev runtime.Event) string {
	if spec.Name != "" {
		return spec.Name
	}
	return ev.Name
}

// beaconKind maps a core EventType to beacon's event-kind vocabulary. Health
// transitions (healthy and unhealthy) both map to the health_status kind; the
// direction becomes the alert level.
func beaconKind(t runtime.EventType) (string, bool) {
	switch t {
	case runtime.EventDie:
		return "die", true
	case runtime.EventOOM:
		return "oom", true
	case runtime.EventHealthStatusHealthy, runtime.EventHealthStatusUnhealthy:
		return "health_status", true
	default:
		return "", false
	}
}
