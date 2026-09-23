// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package delivery is beacon's channel table over courier. courier routes a
// Notification to backends purely by severity level, with no notion of a named
// channel; beacon owns the name-to-channel mapping the charter requires. Each
// operator-named channel becomes one courier.Beacon built from that channel's
// backend config, and Deliver resolves a name to its Beacon and hands off.
//
// beacon governs and routes; courier delivers. New channel types are added in
// courier, never here.
package delivery

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/tagwright/beacon/internal/config"
	"github.com/tagwright/courier"
)

// Deliverer hands a Notification to a named channel. It is the effect edge the
// policy engine drives, kept as an interface so a capturing fake can stand in
// for it in wiring tests.
type Deliverer interface {
	// Deliver sends n through the named channel. A channel that does not
	// resolve is an error, never a silent drop.
	Deliver(ctx context.Context, channel string, n courier.Notification) error
}

// CourierDelivery is the production Deliverer. It holds one courier.Beacon per
// named leaf channel.
type CourierDelivery struct {
	channels  map[string]*courier.Beacon
	minLevels map[string]courier.Level
	logger    *slog.Logger
}

// New builds a CourierDelivery from the operator's channel table. Each named
// channel becomes a single-backend courier.Beacon. Secret-valued settings
// resolve through resolve at send time (courier's injection model). The routing
// engine resolves every name to a configured leaf before delivery, and a
// dangling default_channel is caught at config load, so Deliver never needs a
// default fallback: an unknown leaf here is a hard error, not a silent
// redirect.
func New(channels map[string]config.ChannelConfig, resolve courier.SecretResolver, logger *slog.Logger) (*CourierDelivery, error) {
	if logger == nil {
		logger = slog.Default()
	}
	built := make(map[string]*courier.Beacon, len(channels))
	minLevels := make(map[string]courier.Level, len(channels))
	for name, ch := range channels {
		level, err := ParseLevel(ch.MinLevel)
		if err != nil {
			return nil, fmt.Errorf("beacon: channel %q: %w", name, err)
		}
		b, err := courier.New(courier.Config{
			Channels: []courier.ChannelConfig{{
				Type:     ch.Type,
				MinLevel: level,
				Settings: ch.Settings,
			}},
		}, resolve)
		if err != nil {
			return nil, fmt.Errorf("beacon: build channel %q: %w", name, err)
		}
		built[name] = b
		minLevels[name] = level
	}
	return &CourierDelivery{channels: built, minLevels: minLevels, logger: logger}, nil
}

// Deliver resolves the named leaf channel and hands the notification to its
// courier.Beacon. An unknown leaf is an error, never a silent fallback to the
// default channel: the router already resolved the name to a configured leaf,
// so reaching here with an unknown name is a real misconfiguration. When the
// alert's level is below the leaf's min_level (the one sanctioned post-routing
// drop, which courier applies by returning nil), the delivery engine logs at
// Warn so the silent drop is observable.
func (d *CourierDelivery) Deliver(ctx context.Context, channel string, n courier.Notification) error {
	b, ok := d.channels[channel]
	if !ok {
		return fmt.Errorf("beacon: no channel %q configured", channel)
	}
	if n.Level < d.minLevels[channel] {
		d.logger.Warn("beacon: routed leaf skips alert below its min_level",
			"channel", channel, "alert_level", n.Level.String(), "min_level", d.minLevels[channel].String())
	}
	return b.Notify(ctx, n)
}

// ParseLevel maps a config severity string to a courier.Level. courier
// exposes the constants but no parser, so beacon owns this mapping.
func ParseLevel(s string) (courier.Level, error) {
	switch s {
	case "", "info":
		return courier.LevelInfo, nil
	case "warning", "warn":
		return courier.LevelWarning, nil
	case "error":
		return courier.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q (want info, warning, or error)", s)
	}
}
