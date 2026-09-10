// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package policy is beacon's one governed delivery path. Both ingress paths
// raise a native alert and hand it to this single engine, which normalizes,
// correlates, deduplicates and suppresses storms, resolves the named channel,
// and delivers through courier, not considering the alert done until courier
// confirms delivery or it is safely spooled for retry.
//
// Stage 1 defines the Engine interface and a Pipeline whose stages are present
// but stubbed: normalize passes through, correlate and dedup/suppress are
// no-ops, and delivery goes straight to courier with a spool-on-failure
// fallback. The real correlation window, dedup keying, and airlock storm
// grammar land in later stages against these seams.
package policy

import (
	"context"
	"errors"
	"log/slog"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/delivery"
	"github.com/tagwright/beacon/internal/spool"
)

// Engine is beacon's single governed delivery path. Both ingress paths call
// Process; nothing delivers except through here.
type Engine interface {
	// Process runs one alert through the full pipeline. It returns an error
	// only when the alert could neither be delivered nor safely spooled;
	// a delivered or spooled alert returns nil.
	Process(ctx context.Context, a alert.Alert) error
}

// Clock is the time source, injectable so dedup and suppression windows are
// testable without real time.
type Clock interface {
	Now() int64
}

// Pipeline is the production Engine: normalize -> correlate -> dedup/suppress
// -> resolve channel -> deliver (spool on failure).
type Pipeline struct {
	deliver delivery.Deliverer
	spool   spool.Spooler
	logger  *slog.Logger
}

// New builds a Pipeline over a Deliverer and a Spooler.
func New(deliver delivery.Deliverer, sp spool.Spooler, logger *slog.Logger) *Pipeline {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pipeline{deliver: deliver, spool: sp, logger: logger}
}

// Process runs one alert through the pipeline stages.
func (p *Pipeline) Process(ctx context.Context, a alert.Alert) error {
	a = p.normalize(a)

	if a = p.correlate(a); a.DedupKey == "-suppressed-" {
		// Stage 1 placeholder: correlate never suppresses yet.
		return nil
	}

	if p.suppress(a) {
		return nil
	}

	return p.deliverWithSpool(ctx, a)
}

// normalize fills in derived fields. Stage 1: pass-through with a dedup-key
// backstop so nothing is un-keyed.
func (p *Pipeline) normalize(a alert.Alert) alert.Alert {
	if a.DedupKey == "" {
		a.DedupKey = a.Container + "|" + a.Event
	}
	if a.CorrelationKey == "" {
		a.CorrelationKey = a.Container
	}
	return a
}

// correlate collapses alerts about one incident from different sources.
// Stage 1: no-op.
func (p *Pipeline) correlate(a alert.Alert) alert.Alert {
	return a
}

// suppress applies dedup and airlock's storm grammar. Stage 1: never
// suppresses (first-occurrence-always-fires is trivially satisfied when
// nothing is remembered yet).
func (p *Pipeline) suppress(a alert.Alert) bool {
	return false
}

// deliverWithSpool delivers through courier, spooling on failure so the alert
// is retried rather than dropped. Stage 1 wires the fallback; bounded backoff
// and replay live in the spool package's later implementation.
func (p *Pipeline) deliverWithSpool(ctx context.Context, a alert.Alert) error {
	err := p.deliver.Deliver(ctx, a.Channel, a.Notification)
	if err == nil {
		return nil
	}
	p.logger.Warn("beacon: delivery failed, spooling for retry",
		"channel", a.Channel, "dedup_key", a.DedupKey, "error", err)
	if serr := p.spool.Enqueue(a); serr != nil {
		return errors.Join(err, serr)
	}
	return nil
}
