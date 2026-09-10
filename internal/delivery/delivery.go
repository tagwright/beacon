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
// named channel.
type CourierDelivery struct {
	channels       map[string]*courier.Beacon
	defaultChannel string
}

// New builds a CourierDelivery from the operator's channel table. Each named
// channel becomes a single-backend courier.Beacon. Secret-valued settings
// resolve through resolve at send time (courier's injection model).
func New(channels map[string]config.ChannelConfig, defaultChannel string, resolve courier.SecretResolver) (*CourierDelivery, error) {
	built := make(map[string]*courier.Beacon, len(channels))
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
	}
	if defaultChannel != "" {
		if _, ok := built[defaultChannel]; !ok {
			return nil, fmt.Errorf("beacon: default_channel %q is not a configured channel", defaultChannel)
		}
	}
	return &CourierDelivery{channels: built, defaultChannel: defaultChannel}, nil
}

// Deliver resolves the named channel (falling back to the default when the
// name is empty or unknown) and hands the notification to its courier.Beacon.
func (d *CourierDelivery) Deliver(ctx context.Context, channel string, n courier.Notification) error {
	b, ok := d.channels[channel]
	if !ok {
		if d.defaultChannel == "" {
			return fmt.Errorf("beacon: no channel %q and no default channel configured", channel)
		}
		b = d.channels[d.defaultChannel]
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
