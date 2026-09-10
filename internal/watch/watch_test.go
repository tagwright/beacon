// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package watch

import (
	"context"
	"sync"
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

// reconnectingFake hands out a FRESH event stream on each Watch call, unlike
// runtimetest whose channels are one-shot. The first subscription ends
// immediately (a stream close); the second delivers a die event and then stays
// open until ctx is cancelled. It embeds runtimetest for the other methods
// (Inspect enriches the alert) and shadows Watch.
type reconnectingFake struct {
	*runtimetest.Runtime
	mu    sync.Mutex
	calls int
}

func (f *reconnectingFake) Watch(ctx context.Context) (<-chan runtime.Event, <-chan error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()

	ev := make(chan runtime.Event)
	er := make(chan error, 1)
	if call == 1 {
		// Stream ends right away, as the production failure did.
		close(ev)
		close(er)
		return ev, er
	}
	go func() {
		select {
		case ev <- (runtime.Event{Type: runtime.EventDie, ID: "c1", Name: "web", Labels: beaconLabels()}):
		case <-ctx.Done():
		}
		<-ctx.Done()
		close(ev)
		close(er)
	}()
	return ev, er
}

func (f *reconnectingFake) watchCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// safeCollector is a concurrency-safe emit sink for the reconnect test.
type safeCollector struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (c *safeCollector) emit(ctx context.Context, a alert.Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a)
	return nil
}

func (c *safeCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.alerts)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestRunReconnectsOnStreamEnd is the regression guard for Vikunja #707: a
// watch stream ending must make Run re-subscribe, never exit. The old loop
// returned on the first stream close, killing the process; the fixed loop
// reconnects and the second stream's die event flows through.
func TestRunReconnectsOnStreamEnd(t *testing.T) {
	base := runtimetest.New()
	base.Containers = []runtime.Container{{ID: "c1", Name: "web", ExitCode: 1}}
	f := &reconnectingFake{Runtime: base}
	c := &safeCollector{}
	s := New(f, Config{DefaultChannel: "ops", ReconnectMin: time.Millisecond, ReconnectMax: 5 * time.Millisecond}, clock.Real{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = s.Run(ctx, c.emit); close(done) }()

	// The first subscription ended immediately. Run must reconnect and the
	// second stream's die event must flow through, proving it did not exit.
	waitFor(t, "the reconnected stream's event", func() bool { return c.count() == 1 })
	if f.watchCalls() < 2 {
		t.Fatalf("Run should have re-subscribed, Watch called %d times", f.watchCalls())
	}
	select {
	case <-done:
		t.Fatal("Run exited on a stream end instead of reconnecting")
	default:
	}

	// Run returns only on ctx cancellation.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
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
