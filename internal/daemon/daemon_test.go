// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/beacon/internal/policy"
	"github.com/tagwright/beacon/internal/spool"
	"github.com/tagwright/courier"
	"github.com/tagwright/core/runtime"
	"github.com/tagwright/core/runtime/runtimetest"
)

// fakeDeliverer is a fault-injectable capturing Deliverer.
type fakeDeliverer struct {
	mu   sync.Mutex
	fail bool
	sent int
}

func (f *fakeDeliverer) Deliver(ctx context.Context, channel string, n courier.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("channel down")
	}
	f.sent++
	return nil
}

func (f *fakeDeliverer) setFail(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }
func (f *fakeDeliverer) count() int     { f.mu.Lock(); defer f.mu.Unlock(); return f.sent }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func watchOnlyConfig(spoolDir string) config.Config {
	return config.Config{
		Watch:    config.WatchConfig{Enabled: true, Runtime: "docker", DefaultChannel: "ops"},
		Spool:    config.SpoolConfig{Dir: spoolDir, RetryInterval: 20 * time.Millisecond},
		Dedup:    config.DedupConfig{Window: time.Minute, CorrelationWindow: time.Minute},
		Delivery: config.DeliveryConfig{MaxAttempts: 1},
	}
}

func dieEvent() runtime.Event {
	return runtime.Event{
		Type: runtime.EventDie,
		ID:   "c1",
		Name: "web",
		Labels: map[string]string{
			"beacon.enable":  "true",
			"beacon.channel": "ops",
		},
	}
}

// TestRunWiresWatchToDelivery drives the real Run through the shared runtime
// fake and proves a die event on a labeled container reaches courier via the
// production entrypoint (the built-but-not-wired guard).
func TestRunWiresWatchToDelivery(t *testing.T) {
	d := &fakeDeliverer{}
	sp, err := spool.New(t.TempDir(), 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.New(d, sp, clock.Real{}, policy.Config{
		DedupWindow: time.Minute, CorrelationWindow: time.Minute, MaxAttempts: 1,
	}, nil)
	rt := runtimetest.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Deps{Config: watchOnlyConfig(t.TempDir()), Runtime: rt, Engine: engine, Clock: clock.Real{}}) }()

	rt.Emit(dieEvent())
	waitFor(t, "the die event to be delivered", func() bool { return d.count() == 1 })
}

// TestRunDeliversWatchEventKinds drives the real Run through the runtime fake
// and proves the full charter event set beyond die - oom, an unhealthy
// health_status transition, and a restart loop - each flows through the one
// governed pipeline to delivery. Distinct containers keep correlation from
// collapsing them so each kind is observable.
func TestRunDeliversWatchEventKinds(t *testing.T) {
	d := &fakeDeliverer{}
	sp, err := spool.New(t.TempDir(), 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.New(d, sp, clock.Real{}, policy.Config{
		DedupWindow: time.Minute, CorrelationWindow: time.Minute, MaxAttempts: 1,
	}, nil)
	rt := runtimetest.New()
	rt.Containers = []runtime.Container{
		{ID: "c1", Name: "oomer", OOMKilled: true, ExitCode: 137},
		{ID: "c2", Name: "sicky", Health: "unhealthy"},
		{ID: "c3", Name: "flapper", RestartCount: 9},
	}

	cfg := watchOnlyConfig(t.TempDir())
	cfg.Watch.RestartThreshold = 3
	cfg.Watch.RestartWindow = time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Deps{Config: cfg, Runtime: rt, Engine: engine, Clock: clock.Real{}}) }()

	labels := map[string]string{"beacon.enable": "true", "beacon.channel": "ops"}
	rt.Emit(runtime.Event{Type: runtime.EventOOM, ID: "c1", Name: "oomer", Labels: labels})
	rt.Emit(runtime.Event{Type: runtime.EventHealthStatusUnhealthy, ID: "c2", Name: "sicky", Labels: labels})
	for i := 0; i < 3; i++ { // three starts within the window trip the loop
		rt.Emit(runtime.Event{Type: runtime.EventStart, ID: "c3", Name: "flapper", Labels: labels})
	}

	waitFor(t, "oom, unhealthy, and restart-loop alerts to be delivered", func() bool { return d.count() == 3 })
}

// TestRunAtLeastOnceThroughSeam is the load-bearing fault-injection test at the
// run(Deps) seam: a courier delivery failure must spool the alert and the
// background replayer must deliver it on recovery, never drop it.
func TestRunAtLeastOnceThroughSeam(t *testing.T) {
	d := &fakeDeliverer{fail: true}
	sp, err := spool.New(t.TempDir(), 0, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.New(d, sp, clock.Real{}, policy.Config{
		DedupWindow: time.Minute, CorrelationWindow: time.Minute, MaxAttempts: 1,
	}, nil)
	rt := runtimetest.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Run(ctx, Deps{Config: watchOnlyConfig(t.TempDir()), Runtime: rt, Engine: engine, Clock: clock.Real{}}) }()

	rt.Emit(dieEvent())

	// Delivery is failing, so the alert must land in the spool, not vanish.
	waitFor(t, "the failed alert to be spooled", func() bool {
		n, _ := sp.Len()
		return n == 1
	})
	if d.count() != 0 {
		t.Fatalf("nothing should have delivered while the channel is down, got %d", d.count())
	}

	// Channel recovers; the background replayer must drain the spool.
	d.setFail(false)
	waitFor(t, "the spooled alert to be replayed", func() bool { return d.count() == 1 })
	waitFor(t, "the spool to drain", func() bool { n, _ := sp.Len(); return n == 0 })
}
