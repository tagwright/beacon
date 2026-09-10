// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/courier"
)

// fakeDeliverer is a capturing Deliverer with a fault knob, the shape the
// testing standard requires so the failure path is exercised, not just the
// happy path.
type fakeDeliverer struct {
	mu   sync.Mutex
	fail bool
	sent []courier.Notification
}

func (f *fakeDeliverer) Deliver(ctx context.Context, channel string, n courier.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("channel down")
	}
	f.sent = append(f.sent, n)
	return nil
}

func (f *fakeDeliverer) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

func (f *fakeDeliverer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeDeliverer) last() courier.Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[len(f.sent)-1]
}

// fakeSpooler is an in-memory Spooler with a fault knob.
type fakeSpooler struct {
	mu     sync.Mutex
	items  []alert.Alert
	enqErr error
}

func (f *fakeSpooler) Enqueue(a alert.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enqErr != nil {
		return f.enqErr
	}
	f.items = append(f.items, a)
	return nil
}

func (f *fakeSpooler) Replay(ctx context.Context, deliver func(context.Context, alert.Alert) error) error {
	f.mu.Lock()
	pending := append([]alert.Alert(nil), f.items...)
	f.mu.Unlock()
	var keep []alert.Alert
	for _, a := range pending {
		if err := deliver(ctx, a); err != nil {
			keep = append(keep, a)
		}
	}
	f.mu.Lock()
	f.items = keep
	f.mu.Unlock()
	return nil
}

func (f *fakeSpooler) Len() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.items), nil
}

func newTestPipeline(d *fakeDeliverer, s *fakeSpooler, clk clock.Clock, cfg Config) *Pipeline {
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 1
	}
	return New(d, s, clk, cfg, nil)
}

func watchAlert(container, event string) alert.Alert {
	return alert.Alert{
		Channel:   "ops",
		Source:    alert.SourceWatch,
		Container: container,
		Event:     event,
		Notification: courier.Notification{
			Title: event + ": " + container,
			Level: courier.LevelError,
		},
	}
}

// TestProcessDelivers is the happy path.
func TestProcessDelivers(t *testing.T) {
	d, s := &fakeDeliverer{}, &fakeSpooler{}
	p := newTestPipeline(d, s, clock.Real{}, Config{})
	if err := p.Process(context.Background(), watchAlert("c1", "die")); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if d.count() != 1 {
		t.Errorf("delivered = %d, want 1", d.count())
	}
}

// TestDeliveryFailureSpoolsThenReplays is the load-bearing at-least-once proof:
// a failed delivery is spooled, not dropped, and a later replay delivers it.
func TestDeliveryFailureSpoolsThenReplays(t *testing.T) {
	d, s := &fakeDeliverer{fail: true}, &fakeSpooler{}
	p := newTestPipeline(d, s, clock.Real{}, Config{})

	if err := p.Process(context.Background(), watchAlert("c1", "die")); err != nil {
		t.Fatalf("Process should spool, not error: %v", err)
	}
	if d.count() != 0 {
		t.Fatalf("nothing should have delivered while the channel is down")
	}
	if n, _ := s.Len(); n != 1 {
		t.Fatalf("spooled = %d, want 1 (alert must not be dropped)", n)
	}

	// Channel recovers; replay must deliver the spooled alert and clear it.
	d.setFail(false)
	p.replayOnce(context.Background())
	if d.count() != 1 {
		t.Errorf("replay delivered = %d, want 1", d.count())
	}
	if n, _ := s.Len(); n != 0 {
		t.Errorf("spool should be empty after successful replay, got %d", n)
	}
}

// TestDeliveryAndSpoolFailSurfaces is the one case an alert is truly lost: it
// must surface as an error, never a silent success.
func TestDeliveryAndSpoolFailSurfaces(t *testing.T) {
	d := &fakeDeliverer{fail: true}
	s := &fakeSpooler{enqErr: errors.New("disk full")}
	p := newTestPipeline(d, s, clock.Real{}, Config{})
	if err := p.Process(context.Background(), watchAlert("c1", "die")); err == nil {
		t.Fatal("Process must return an error when delivery and spooling both fail")
	}
}

// TestDedupSuppressesRepeatWithinWindow proves airlock's grammar: first fires,
// a repeat within the window is digested, and after the window it fires again
// carrying the suppressed count.
func TestDedupSuppressesRepeatWithinWindow(t *testing.T) {
	d, s := &fakeDeliverer{}, &fakeSpooler{}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	// Disable correlation so this isolates the dedup layer.
	p := newTestPipeline(d, s, clk, Config{DedupWindow: 5 * time.Minute, CorrelationWindow: 0})

	if err := p.Process(context.Background(), watchAlert("c1", "die")); err != nil {
		t.Fatal(err)
	}
	if d.count() != 1 {
		t.Fatalf("first alert should fire, got %d", d.count())
	}

	// Repeat within the window: digested.
	_ = p.Process(context.Background(), watchAlert("c1", "die"))
	if d.count() != 1 {
		t.Fatalf("repeat within window must be suppressed, delivered = %d", d.count())
	}

	// After the window: fires again, and reports the suppressed count.
	clk.Advance(6 * time.Minute)
	_ = p.Process(context.Background(), watchAlert("c1", "die"))
	if d.count() != 2 {
		t.Fatalf("after window a repeat should fire, delivered = %d", d.count())
	}
	if !strings.Contains(d.last().Body, "1 suppressed") {
		t.Errorf("re-fired alert should report the suppressed count, body = %q", d.last().Body)
	}
}

// TestCorrelationCollapsesSameIncident proves two different events about one
// container collapse into a single delivered alert within the correlation
// window.
func TestCorrelationCollapsesSameIncident(t *testing.T) {
	d, s := &fakeDeliverer{}, &fakeSpooler{}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	p := newTestPipeline(d, s, clk, Config{DedupWindow: 5 * time.Minute, CorrelationWindow: 5 * time.Minute})

	// A health_status and a Gatus DOWN for the same container are one incident.
	_ = p.Process(context.Background(), watchAlert("c1", "health_status"))
	gatus := watchAlert("c1", "gatus")
	_ = p.Process(context.Background(), gatus)

	if d.count() != 1 {
		t.Errorf("same-incident alerts should collapse to one, delivered = %d", d.count())
	}
}

// TestDistinctIncidentsBothFire guards against over-collapsing: two different
// containers are two incidents.
func TestDistinctIncidentsBothFire(t *testing.T) {
	d, s := &fakeDeliverer{}, &fakeSpooler{}
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	p := newTestPipeline(d, s, clk, Config{DedupWindow: 5 * time.Minute, CorrelationWindow: 5 * time.Minute})

	_ = p.Process(context.Background(), watchAlert("c1", "die"))
	_ = p.Process(context.Background(), watchAlert("c2", "die"))
	if d.count() != 2 {
		t.Errorf("distinct containers should both fire, delivered = %d", d.count())
	}
}
