// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package policy is beacon's one governed delivery path. Both ingress paths
// raise a native alert and hand it to this single engine, which normalizes,
// correlates, deduplicates and suppresses storms, resolves the named channel,
// and delivers through courier, not considering the alert done until courier
// confirms delivery or it is safely spooled for retry.
//
// The pipeline is: normalize, correlate, dedup and suppress, resolve channel,
// deliver with spool. Correlation collapses a watch event and an ingested alert
// about the same incident into one. Dedup and storm suppression follow
// airlock's grammar (a window anchored on the last fire, the first occurrence
// fires, repeats within the window are digested), applied to both ingress
// paths so the suite has one storm model. Delivery is at-least-once: bounded
// in-line retry with backoff, then a durable spool that a background replayer
// drains, so an alert is never silently dropped.
package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/delivery"
	"github.com/tagwright/beacon/internal/spool"
	"github.com/tagwright/courier"
)

// Engine is beacon's single governed delivery path. Both ingress paths call
// Process; nothing delivers except through here.
type Engine interface {
	// Process runs one alert through the full pipeline. It returns an error
	// only when the alert could neither be delivered nor safely spooled; a
	// delivered, spooled, or intentionally suppressed alert returns nil.
	Process(ctx context.Context, a alert.Alert) error
}

// Config tunes the pipeline.
type Config struct {
	// DedupWindow is the default storm window (a per-alert MinInterval
	// overrides it).
	DedupWindow time.Duration
	// CorrelationWindow is how long a first alert about an incident holds
	// the floor so a second from another source collapses into it.
	CorrelationWindow time.Duration
	// MaxAttempts is the number of in-line delivery attempts before spooling.
	MaxAttempts int
	// InitialBackoff and MaxBackoff bound the in-line retry backoff.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// Pipeline is the production Engine.
type Pipeline struct {
	deliver   delivery.Deliverer
	spool     spool.Spooler
	clock     clock.Clock
	cfg       Config
	dedup     *suppressor
	correlate *suppressor
	logger    *slog.Logger
}

// New builds a Pipeline.
func New(deliver delivery.Deliverer, sp spool.Spooler, clk clock.Clock, cfg Config, logger *slog.Logger) *Pipeline {
	if logger == nil {
		logger = slog.Default()
	}
	if clk == nil {
		clk = clock.Real{}
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}
	return &Pipeline{
		deliver:   deliver,
		spool:     sp,
		clock:     clk,
		cfg:       cfg,
		dedup:     newSuppressor(clk, cfg.DedupWindow),
		correlate: newSuppressor(clk, cfg.CorrelationWindow),
		logger:    logger,
	}
}

// Process runs one alert through the pipeline.
func (p *Pipeline) Process(ctx context.Context, a alert.Alert) error {
	a = p.normalize(a)

	// Correlate (coarse): if another alert about this incident fired within
	// the correlation window, collapse this one into it.
	if p.correlate.suppressedRecently(a.CorrelationKey, p.cfg.CorrelationWindow) {
		return nil
	}

	// Dedup and suppress (fine): if this same alert fired within its window,
	// digest it. A per-container min-interval label overrides the window.
	if p.dedup.suppressedRecently(a.DedupKey, a.MinInterval) {
		return nil
	}

	// Decided to fire: commit both windows.
	sinceLast := p.dedup.recordFired(a.DedupKey, a.Channel, a.Notification.Title)
	p.correlate.recordFired(a.CorrelationKey, a.Channel, a.Notification.Title)
	if sinceLast > 0 {
		a = annotateSuppressed(a, sinceLast)
	}

	return p.deliverWithSpool(ctx, a)
}

// normalize fills in derived fields so nothing is un-keyed.
func (p *Pipeline) normalize(a alert.Alert) alert.Alert {
	if a.Time.IsZero() {
		a.Time = p.clock.Now()
	}
	if a.DedupKey == "" {
		a.DedupKey = a.Container + "|" + a.Event
	}
	if a.CorrelationKey == "" {
		a.CorrelationKey = a.Container
		if a.CorrelationKey == "" {
			// An alert with no container correlates only to itself.
			a.CorrelationKey = a.DedupKey
		}
	}
	return a
}

// deliverWithSpool delivers with bounded retry and spools on failure so the
// alert is replayed rather than dropped. It returns an error only when both
// delivery and spooling fail, which is the one case an alert is actually lost.
func (p *Pipeline) deliverWithSpool(ctx context.Context, a alert.Alert) error {
	if err := p.attempt(ctx, a); err != nil {
		p.logger.Warn("beacon: delivery failed, spooling for retry",
			"channel", a.Channel, "dedup_key", a.DedupKey, "error", err)
		if serr := p.spool.Enqueue(a); serr != nil {
			return errors.Join(err, serr)
		}
	}
	return nil
}

// attempt delivers with bounded exponential backoff between attempts.
func (p *Pipeline) attempt(ctx context.Context, a alert.Alert) error {
	backoff := p.cfg.InitialBackoff
	var err error
	for i := 0; i < p.cfg.MaxAttempts; i++ {
		if i > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			if backoff = backoff * 2; backoff > p.cfg.MaxBackoff && p.cfg.MaxBackoff > 0 {
				backoff = p.cfg.MaxBackoff
			}
		}
		if err = p.deliver.Deliver(ctx, a.Channel, a.Notification); err == nil {
			return nil
		}
	}
	return err
}

// RunReplayer drains the spool on start (recovery) and then on every interval,
// delivering each spooled alert directly (bypassing the storm counter, so a
// backlog draining after an outage is not mistaken for a storm). It blocks
// until ctx is cancelled.
func (p *Pipeline) RunReplayer(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	p.replayOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.replayOnce(ctx)
		}
	}
}

func (p *Pipeline) replayOnce(ctx context.Context) {
	err := p.spool.Replay(ctx, func(ctx context.Context, a alert.Alert) error {
		return p.deliver.Deliver(ctx, a.Channel, a.Notification)
	})
	if err != nil && ctx.Err() == nil {
		p.logger.Warn("beacon: spool replay pass failed", "error", err)
	}
}

// RunDigester emits a periodic suppression digest per channel, if interval is
// positive. It blocks until ctx is cancelled.
func (p *Pipeline) RunDigester(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.emitDigest(ctx)
		}
	}
}

// emitDigest drains the dedup suppressor and delivers one rollup per channel.
func (p *Pipeline) emitDigest(ctx context.Context) {
	items := p.dedup.drainDigest()
	if len(items) == 0 {
		return
	}
	byChannel := make(map[string][]digestItem)
	for _, it := range items {
		byChannel[it.Channel] = append(byChannel[it.Channel], it)
	}
	for channel, list := range byChannel {
		total := 0
		body := ""
		for _, it := range list {
			total += it.Count
			body += fmt.Sprintf("  %s: %d suppressed\n", it.Title, it.Count)
		}
		n := courier.Notification{
			Title: fmt.Sprintf("beacon: %d suppressed alerts digested", total),
			Body:  body,
			Level: courier.LevelInfo,
		}
		if err := p.deliver.Deliver(ctx, channel, n); err != nil {
			p.logger.Warn("beacon: digest delivery failed", "channel", channel, "error", err)
		}
	}
}

// annotateSuppressed appends the suppressed-since-last-alert count to the
// alert body, matching airlock's immediate surface.
func annotateSuppressed(a alert.Alert, sinceLast int) alert.Alert {
	suffix := fmt.Sprintf("(%d suppressed since the last alert for this identity)", sinceLast)
	if a.Notification.Body == "" {
		a.Notification.Body = suffix
	} else {
		a.Notification.Body = a.Notification.Body + "\n" + suffix
	}
	return a
}
