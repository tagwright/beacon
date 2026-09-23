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
	"sort"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/beacon/internal/clock"
	"github.com/tagwright/beacon/internal/delivery"
	"github.com/tagwright/beacon/internal/history"
	"github.com/tagwright/beacon/internal/routing"
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
	// DedupWindow is the default storm window (a per-alert MinInterval or a
	// per-rule repeat_after overrides it).
	DedupWindow time.Duration
	// CorrelationWindow is how long a first alert about an incident holds
	// the floor so a second from another source collapses into it.
	CorrelationWindow time.Duration
	// MaxAttempts is the number of in-line delivery attempts before spooling.
	MaxAttempts int
	// InitialBackoff and MaxBackoff bound the in-line retry backoff.
	InitialBackoff time.Duration
	MaxBackoff     time.Duration

	// Router resolves an alert's channel name through the ruleset tree to the
	// leaf set. Nil routes the alert's channel name directly to itself as a
	// single leaf (the pre-routing behavior), which keeps the unit tests that
	// do not exercise routing unchanged.
	Router *routing.Engine
	// History records every processed event, unconditionally, after routing
	// and before the suppression gates. Nil disables recording.
	History history.Recorder
	// NotifyOnResolved is the fleet policy for a firing-to-resolved recovery.
	// Nil defaults ON; a false value drops a resolved alert after the history
	// write and before correlate.
	NotifyOnResolved *bool
	// WatchDefault and IngestDefault are the resolvable fleet defaults each
	// ingress path falls back to when an alert names no channel or an unknown
	// one.
	WatchDefault  string
	IngestDefault string
}

// Pipeline is the production Engine.
type Pipeline struct {
	deliver          delivery.Deliverer
	spool            spool.Spooler
	clock            clock.Clock
	cfg              Config
	dedup            *suppressor
	correlate        *suppressor
	state            *stateEngine
	router           *routing.Engine
	history          history.Recorder
	notifyOnResolved bool
	watchDefault     string
	ingestDefault    string
	logger           *slog.Logger
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
	notify := cfg.NotifyOnResolved == nil || *cfg.NotifyOnResolved
	return &Pipeline{
		deliver:          deliver,
		spool:            sp,
		clock:            clk,
		cfg:              cfg,
		dedup:            newSuppressor(clk, cfg.DedupWindow),
		correlate:        newSuppressor(clk, cfg.CorrelationWindow),
		state:            newStateEngine(),
		router:           cfg.Router,
		history:          cfg.History,
		notifyOnResolved: notify,
		watchDefault:     cfg.WatchDefault,
		ingestDefault:    cfg.IngestDefault,
		logger:           logger,
	}
}

// Process runs one alert through the pipeline. The order is: normalize,
// resolution state (before the router so a rule can match on state), resolve the
// tree to leaves, write history unconditionally, apply the resolve gate,
// correlate once, then per-leaf dedup and deliver.
func (p *Pipeline) Process(ctx context.Context, a alert.Alert) error {
	a = p.normalize(a)

	// Resolution state: finalize Alert.State (and phrase it) before the router.
	p.state.apply(&a)

	// Resolve the channel name through the ruleset tree to the leaf set, each
	// leaf carrying its effective repeat_after (the max over every matched rule
	// on every path that reached it).
	leaves := p.resolve(&a)

	// History write: unconditional, after routing and before the suppression
	// gates, so replay sees events the live ruleset would suppress.
	if p.history != nil {
		if err := p.history.Record(historyRecord(a, leaves)); err != nil {
			p.logger.Warn("beacon: history record failed", "dedup_key", a.DedupKey, "error", err)
		}
	}

	// Resolve gate: when notify-on-resolved is off, a recovery is dropped here.
	if !p.notifyOnResolved && a.State == alert.StateResolved {
		return nil
	}

	// Correlate (coarse, once, keyed by container plus state): if another alert
	// about this incident fired within the window, collapse this one into it.
	corrKey := a.CorrelationKey + "|" + string(a.State)
	if p.correlate.suppressedRecently(corrKey, p.cfg.CorrelationWindow) {
		return nil
	}

	// Per-leaf dedup and delivery. The suppressor key is DedupKey|leaf|state, so
	// two fanned leaves suppress independently and a resolve is never suppressed
	// as a repeat of its firing, while repeated resolves still dedup among
	// themselves.
	var errs []error
	firedAny := false
	for _, leaf := range sortedLeaves(leaves) {
		window := a.MinInterval
		if ra := leaves[leaf]; ra > window {
			window = ra
		}
		key := a.DedupKey + "|" + leaf + "|" + string(a.State)
		if p.dedup.suppressedRecently(key, window) {
			continue
		}
		sinceLast := p.dedup.recordFired(key, leaf, a.Notification.Title)
		la := a
		la.Channel = leaf
		if sinceLast > 0 {
			la = annotateSuppressed(la, sinceLast)
		}
		firedAny = true
		if err := p.deliverWithSpool(ctx, la); err != nil {
			errs = append(errs, err)
		}
	}
	if firedAny {
		p.correlate.recordFired(corrKey, a.Channel, a.Notification.Title)
	}
	return errors.Join(errs...)
}

// resolve turns the alert's channel name into the leaf set. With no router
// configured it routes the name directly to itself, preserving the pre-routing
// single-leaf behavior.
func (p *Pipeline) resolve(a *alert.Alert) map[string]time.Duration {
	if p.router == nil {
		return map[string]time.Duration{a.Channel: 0}
	}
	fleet := p.watchDefault
	if a.Source == alert.SourceIngest {
		fleet = p.ingestDefault
	}
	dec := p.router.Resolve(routing.Input{
		Channel:  a.Channel,
		Event:    a.Event,
		Source:   string(a.Source),
		Severity: a.Severity,
		Labels:   a.Labels,
		State:    string(a.State),
		Time:     a.Time,
	}, fleet)
	if dec.UsedFleetDefault {
		p.logger.Warn("beacon: channel names nothing in either map, routed to fleet default",
			"channel", a.Channel, "container", a.Container, "fleet_default", fleet)
	}
	return dec.Leaves
}

// sortedLeaves returns the leaf names in a stable order so delivery and tests
// are deterministic.
func sortedLeaves(leaves map[string]time.Duration) []string {
	out := make([]string, 0, len(leaves))
	for name := range leaves {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// historyRecord builds a store record from a processed alert and its routing
// decision.
func historyRecord(a alert.Alert, leaves map[string]time.Duration) history.Record {
	return history.Record{
		Time:     a.Time,
		Source:   string(a.Source),
		Event:    a.Event,
		Severity: a.Severity,
		Labels:   a.Labels,
		State:    string(a.State),
		Channel:  a.Channel,
		DedupKey: a.DedupKey,
		Title:    a.Notification.Title,
		Level:    a.Notification.Level.String(),
		Leaves:   sortedLeaves(leaves),
	}
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
