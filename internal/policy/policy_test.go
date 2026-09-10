// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/courier"
)

// fakeDeliverer is a capturing Deliverer with a fault knob, the shape the
// testing standard requires so the failure path is exercised, not just the
// happy path.
type fakeDeliverer struct {
	err       error
	delivered int
}

func (f *fakeDeliverer) Deliver(ctx context.Context, channel string, n courier.Notification) error {
	if f.err != nil {
		return f.err
	}
	f.delivered++
	return nil
}

// fakeSpooler is a capturing Spooler with a fault knob.
type fakeSpooler struct {
	err     error
	spooled int
}

func (f *fakeSpooler) Enqueue(a alert.Alert) error {
	if f.err != nil {
		return f.err
	}
	f.spooled++
	return nil
}

func (f *fakeSpooler) Replay(ctx context.Context, deliver func(context.Context, alert.Alert) error) error {
	return nil
}

func (f *fakeSpooler) Len() (int, error) { return f.spooled, nil }

// TestProcessDelivers is the happy path.
func TestProcessDelivers(t *testing.T) {
	d := &fakeDeliverer{}
	s := &fakeSpooler{}
	p := New(d, s, nil)
	if err := p.Process(context.Background(), alert.Alert{Channel: "ops", Container: "c1", Event: "die"}); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if d.delivered != 1 {
		t.Errorf("delivered = %d, want 1", d.delivered)
	}
}

// TestDeliveryFailureSpools proves an alert that fails delivery is spooled
// rather than dropped, the whole point of at-least-once.
func TestDeliveryFailureSpools(t *testing.T) {
	d := &fakeDeliverer{err: errors.New("channel down")}
	s := &fakeSpooler{}
	p := New(d, s, nil)
	if err := p.Process(context.Background(), alert.Alert{Channel: "ops", Container: "c1", Event: "die"}); err != nil {
		t.Fatalf("Process should not error when the alert is spooled: %v", err)
	}
	if s.spooled != 1 {
		t.Errorf("spooled = %d, want 1", s.spooled)
	}
}
