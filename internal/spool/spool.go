// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package spool is beacon's at-least-once store. Delivery is at-least-once: on
// failure beacon retries with bounded backoff, and an alert that outlives the
// retry window is spooled to disk and replayed on recovery, so an alert is
// never silently dropped. Duplicates from retry or replay are tolerable and
// are collapsed by the policy engine's dedup layer; a missed alert is the
// failure a notifier must not have.
//
// Stage 1 defines the interface and a compiling stub. The durable disk format,
// bounded backoff, replay-on-recovery, and dedup-on-replay are implemented in
// a later stage against this seam.
package spool

import (
	"context"
	"errors"

	"github.com/tagwright/beacon/internal/alert"
)

// ErrNotImplemented marks a spool operation whose real behavior lands in a
// later build stage.
var ErrNotImplemented = errors.New("beacon: spool not implemented yet")

// Spooler persists undelivered alerts and replays them on recovery. It is kept
// as an interface so a fault-injecting fake can drive the failure paths in
// wiring tests, which is where an at-least-once guarantee is actually proven.
type Spooler interface {
	// Enqueue persists an alert that could not be delivered, so it
	// survives a restart and is replayed later.
	Enqueue(a alert.Alert) error

	// Replay redelivers every spooled alert through deliver, removing each
	// one that deliver accepts. deliver is expected to be idempotent at the
	// dedup layer, since replay can produce duplicates.
	Replay(ctx context.Context, deliver func(context.Context, alert.Alert) error) error

	// Len reports how many alerts are currently spooled.
	Len() (int, error)
}

// DiskSpool is the production Spooler, persisting to a durable directory.
// Stage 1 is a compiling stub.
type DiskSpool struct {
	dir        string
	maxRetries int
}

// New constructs a DiskSpool over the given directory.
func New(dir string, maxRetries int) *DiskSpool {
	return &DiskSpool{dir: dir, maxRetries: maxRetries}
}

// Enqueue is not implemented in Stage 1.
func (s *DiskSpool) Enqueue(a alert.Alert) error {
	return ErrNotImplemented
}

// Replay is not implemented in Stage 1.
func (s *DiskSpool) Replay(ctx context.Context, deliver func(context.Context, alert.Alert) error) error {
	return ErrNotImplemented
}

// Len is not implemented in Stage 1.
func (s *DiskSpool) Len() (int, error) {
	return 0, ErrNotImplemented
}
