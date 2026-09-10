// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package watch

import (
	"context"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/courier"
	"github.com/tagwright/core/runtime"
	"github.com/tagwright/core/runtime/runtimetest"
)

func beaconLabels() map[string]string {
	return map[string]string{
		"beacon.enable":  "true",
		"beacon.channel": "ops",
	}
}

// collector captures emitted alerts.
type collector struct{ alerts []alert.Alert }

func (c *collector) emit(ctx context.Context, a alert.Alert) error {
	c.alerts = append(c.alerts, a)
	return nil
}

func newSourceWith(rt runtime.Runtime, clk clock.Clock) *Source {
	return New(rt, Config{DefaultChannel: "ops", RestartThreshold: 3, RestartWindow: time.Minute}, clk, nil)
}

func TestRestartDetector(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	d := newRestartDetector(clk, 3, time.Minute)

	// A fresh start (RestartCount 0) is never a loop.
	if d.observe("c1", 0) {
		t.Fatal("a first start must not be a loop")
	}
	// Three restarts within the window: the third crosses the threshold.
	if d.observe("c1", 1) || d.observe("c1", 2) {
		t.Fatal("below threshold should not fire")
	}
	if !d.observe("c1", 3) {
		t.Fatal("third restart within window should declare a loop")
	}
	// Cooldown: the next start does not immediately re-fire.
	if d.observe("c1", 4) {
		t.Fatal("cooldown should suppress an immediate re-fire")
	}
}

func TestRestartDetectorWindowExpiry(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	d := newRestartDetector(clk, 3, time.Minute)
	d.observe("c1", 1)
	clk.Advance(2 * time.Minute) // first restart falls out of the window
	d.observe("c1", 2)
	if d.observe("c1", 3) {
		t.Fatal("restarts spread beyond the window should not be a loop")
	}
}

func TestSourceRaisesOOM(t *testing.T) {
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{ID: "c1", Name: "web", OOMKilled: true, ExitCode: 137}}
	s := newSourceWith(rt, clock.Real{})
	c := &collector{}

	s.handle(context.Background(), runtime.Event{Type: runtime.EventOOM, ID: "c1", Name: "web", Labels: beaconLabels()}, c.emit)
	if len(c.alerts) != 1 {
		t.Fatalf("oom should raise one alert, got %d", len(c.alerts))
	}
	a := c.alerts[0]
	if a.Event != "oom" || a.Notification.Level != courier.LevelError {
		t.Errorf("oom alert = %q level %v", a.Event, a.Notification.Level)
	}
	if a.Notification.Fields["oom_killed"] != "true" {
		t.Errorf("oom alert should carry oom_killed, fields %v", a.Notification.Fields)
	}
}

func TestSourceRaisesUnhealthy(t *testing.T) {
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{ID: "c1", Name: "web", Health: "unhealthy"}}
	s := newSourceWith(rt, clock.Real{})
	c := &collector{}

	s.handle(context.Background(), runtime.Event{Type: runtime.EventHealthStatusUnhealthy, ID: "c1", Name: "web", Labels: beaconLabels()}, c.emit)
	if len(c.alerts) != 1 {
		t.Fatalf("unhealthy should raise one alert, got %d", len(c.alerts))
	}
	a := c.alerts[0]
	if a.Event != "health_status" || a.Notification.Level != courier.LevelError {
		t.Errorf("unhealthy alert = %q level %v", a.Event, a.Notification.Level)
	}
}

func TestSourceHealthyIsRecovery(t *testing.T) {
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{ID: "c1", Name: "web", Health: "healthy"}}
	s := newSourceWith(rt, clock.Real{})
	c := &collector{}

	s.handle(context.Background(), runtime.Event{Type: runtime.EventHealthStatusHealthy, ID: "c1", Name: "web", Labels: beaconLabels()}, c.emit)
	if len(c.alerts) != 1 {
		t.Fatalf("healthy should raise one recovery alert, got %d", len(c.alerts))
	}
	if c.alerts[0].Notification.Level != courier.LevelInfo {
		t.Errorf("a healthy transition should be info level, got %v", c.alerts[0].Notification.Level)
	}
}

func TestSourceDieCarriesExitCode(t *testing.T) {
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{ID: "c1", Name: "web", ExitCode: 1}}
	s := newSourceWith(rt, clock.Real{})
	c := &collector{}

	s.handle(context.Background(), runtime.Event{Type: runtime.EventDie, ID: "c1", Name: "web", Labels: beaconLabels()}, c.emit)
	if len(c.alerts) != 1 {
		t.Fatalf("die should raise one alert, got %d", len(c.alerts))
	}
	if c.alerts[0].Notification.Fields["exit_code"] != "1" {
		t.Errorf("die alert should carry exit_code, fields %v", c.alerts[0].Notification.Fields)
	}
}

func TestSourceRestartLoopRaisesAlert(t *testing.T) {
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{ID: "c1", Name: "web", RestartCount: 5}}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	s := newSourceWith(rt, clk)
	c := &collector{}

	start := runtime.Event{Type: runtime.EventStart, ID: "c1", Name: "web", Labels: beaconLabels()}
	s.handle(context.Background(), start, c.emit)
	s.handle(context.Background(), start, c.emit)
	if len(c.alerts) != 0 {
		t.Fatalf("below threshold no restart alert, got %d", len(c.alerts))
	}
	s.handle(context.Background(), start, c.emit) // third start crosses threshold
	if len(c.alerts) != 1 {
		t.Fatalf("restart loop should raise one alert, got %d", len(c.alerts))
	}
	if c.alerts[0].Event != "restart" {
		t.Errorf("event = %q, want restart", c.alerts[0].Event)
	}
}

func TestSourceIgnoresUnlabeledContainer(t *testing.T) {
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{ID: "c1", Name: "web"}}
	s := newSourceWith(rt, clock.Real{})
	c := &collector{}

	// No beacon.enable label: ignored.
	s.handle(context.Background(), runtime.Event{Type: runtime.EventDie, ID: "c1", Name: "web"}, c.emit)
	if len(c.alerts) != 0 {
		t.Errorf("an unlabeled container must be ignored, got %d alerts", len(c.alerts))
	}
}
