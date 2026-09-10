// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package spool is beacon's at-least-once store. Delivery is at-least-once: on
// failure beacon retries in line with bounded backoff, and an alert that still
// fails is written here, to disk, so it survives a restart and is replayed on
// recovery. An alert is never silently dropped, which is the whole purpose of
// the tool. Duplicates from replay are tolerable and are collapsed by the
// policy engine's dedup layer; a missed alert is the failure a notifier must
// not have.
//
// The on-disk format is one JSON file per alert, written atomically (temp file
// plus rename) so a crash mid-write never leaves a half-file a replay would
// choke on. Replay delivers each spooled alert directly, bypassing the storm
// counter, so a backlog draining after an outage is not mistaken for a storm
// and mass-suppressed (dedup-on-replay).
package spool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
)

// Spooler persists undelivered alerts and replays them on recovery. It is kept
// as an interface so a fault-injecting fake can drive the failure paths in
// wiring tests, which is where an at-least-once guarantee is actually proven.
type Spooler interface {
	// Enqueue persists an alert that could not be delivered, so it
	// survives a restart and is replayed later.
	Enqueue(a alert.Alert) error

	// Replay redelivers every spooled alert through deliver, removing each
	// one deliver accepts and dropping any that has outlived MaxAge.
	// deliver is expected to be idempotent at the dedup layer, since replay
	// can produce duplicates.
	Replay(ctx context.Context, deliver func(context.Context, alert.Alert) error) error

	// Len reports how many alerts are currently spooled.
	Len() (int, error)
}

const spoolExt = ".json"

// DiskSpool is the production Spooler, persisting to a durable directory.
type DiskSpool struct {
	dir    string
	maxAge time.Duration
	clock  clock.Clock
	seq    atomic.Uint64
	mu     sync.Mutex
}

// New constructs a DiskSpool over dir, creating it if needed. maxAge bounds how
// long an alert is retried before it is abandoned; zero retries indefinitely.
func New(dir string, maxAge time.Duration, clk clock.Clock) (*DiskSpool, error) {
	if clk == nil {
		clk = clock.Real{}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("beacon: spool dir %q: %w", dir, err)
	}
	return &DiskSpool{dir: dir, maxAge: maxAge, clock: clk}, nil
}

// Enqueue writes an alert to the spool atomically.
func (s *DiskSpool) Enqueue(a alert.Alert) error {
	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("beacon: spool marshal: %w", err)
	}
	name := fmt.Sprintf("%020d-%06d%s", s.clock.Now().UnixNano(), s.seq.Add(1), spoolExt)
	final := filepath.Join(s.dir, name)
	tmp := final + ".tmp"

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("beacon: spool write: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("beacon: spool commit: %w", err)
	}
	return nil
}

// Replay attempts delivery of every spooled alert in enqueue order. An alert
// deliver accepts is removed; one that has outlived maxAge is dropped; one that
// still fails is left for the next pass. Replay does not abort on a single
// delivery failure, it moves on so a bad channel does not block the rest.
func (s *DiskSpool) Replay(ctx context.Context, deliver func(context.Context, alert.Alert) error) error {
	files, err := s.list()
	if err != nil {
		return err
	}
	now := s.clock.Now()
	for _, f := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		path := filepath.Join(s.dir, f)
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		var a alert.Alert
		if uerr := json.Unmarshal(data, &a); uerr != nil {
			// A corrupt entry cannot be delivered or fixed; remove it so
			// it does not wedge every future replay.
			_ = os.Remove(path)
			continue
		}
		if s.maxAge > 0 && !a.Time.IsZero() && now.Sub(a.Time) > s.maxAge {
			_ = os.Remove(path)
			continue
		}
		if derr := deliver(ctx, a); derr == nil {
			_ = os.Remove(path)
		}
	}
	return nil
}

// Len reports how many alerts are currently spooled.
func (s *DiskSpool) Len() (int, error) {
	files, err := s.list()
	if err != nil {
		return 0, err
	}
	return len(files), nil
}

func (s *DiskSpool) list() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("beacon: spool list: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != spoolExt {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	return files, nil
}
