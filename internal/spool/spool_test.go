// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package spool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/courier"
)

func testAlert(dedup string) alert.Alert {
	return alert.Alert{
		Channel:  "ops",
		DedupKey: dedup,
		Time:     time.Unix(1_000_000, 0),
		Notification: courier.Notification{
			Title: "t",
			Level: courier.LevelError,
		},
	}
}

func TestEnqueueReplayDelivers(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	s, err := New(t.TempDir(), 0, clk)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(testAlert("c1|die")); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Len(); n != 1 {
		t.Fatalf("Len = %d, want 1", n)
	}

	var delivered []alert.Alert
	if err := s.Replay(context.Background(), func(ctx context.Context, a alert.Alert) error {
		delivered = append(delivered, a)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 1 || delivered[0].DedupKey != "c1|die" {
		t.Fatalf("replay delivered %+v", delivered)
	}
	if n, _ := s.Len(); n != 0 {
		t.Errorf("delivered alert should be removed, Len = %d", n)
	}
}

func TestReplayKeepsOnFailure(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	s, _ := New(t.TempDir(), 0, clk)
	_ = s.Enqueue(testAlert("c1|die"))

	err := s.Replay(context.Background(), func(ctx context.Context, a alert.Alert) error {
		return errors.New("still down")
	})
	if err != nil {
		t.Fatalf("Replay itself should not error on a delivery failure: %v", err)
	}
	if n, _ := s.Len(); n != 1 {
		t.Errorf("a failed delivery must stay spooled, Len = %d", n)
	}
}

func TestReplayDropsExpired(t *testing.T) {
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	s, _ := New(t.TempDir(), time.Minute, clk)
	_ = s.Enqueue(testAlert("c1|die")) // Time is at 1_000_000

	clk.Advance(2 * time.Minute) // now past maxAge
	delivered := 0
	_ = s.Replay(context.Background(), func(ctx context.Context, a alert.Alert) error {
		delivered++
		return nil
	})
	if delivered != 0 {
		t.Errorf("expired alert should be dropped, not delivered")
	}
	if n, _ := s.Len(); n != 0 {
		t.Errorf("expired alert should be removed, Len = %d", n)
	}
}

func TestEnqueuePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	s1, _ := New(dir, 0, clk)
	_ = s1.Enqueue(testAlert("c1|die"))

	// A fresh spool over the same dir sees the persisted alert (survives a
	// container recreate).
	s2, err := New(dir, 0, clk)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := s2.Len(); n != 1 {
		t.Errorf("spooled alert should survive a restart, Len = %d", n)
	}
}
