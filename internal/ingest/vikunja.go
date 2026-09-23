// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// This file is the Vikunja ingest adapter, the first instance of the generalized
// signed-webhook contract: any HMAC-signing source becomes a beacon source. It
// is built against Vikunja's verified source shapes (github.com/go-vikunja,
// pkg/models). Vikunja signs its webhook body with HMAC-SHA256, lowercase hex,
// in X-Vikunja-Signature, which is byte-for-byte beacon's own scheme with a
// different header and key, so verification reuses HMACAuth with that header.
package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tagwright/beacon/internal/alert"
	"github.com/tagwright/courier"
)

// vikunjaEnvelope is Vikunja's WebhookPayload: an event name, an RFC3339 time,
// and the per-event data object.
type vikunjaEnvelope struct {
	EventName string          `json:"event_name"`
	Time      string          `json:"time"`
	Data      json.RawMessage `json:"data"`
}

// vikunjaTask is the subset of Vikunja's Task the adapter carries. DueDate is a
// value time.Time, so the zero value (0001-01-01T00:00:00Z) means unset.
type vikunjaTask struct {
	ID         int64     `json:"id"`
	Title      string    `json:"title"`
	Identifier string    `json:"identifier"`
	DueDate    time.Time `json:"due_date"`
	Index      int64     `json:"index"`
}

// VikunjaAdapter parses a signed Vikunja webhook into one or more native alerts.
type VikunjaAdapter struct{}

// Adapt decodes the verified envelope and maps each supported event to an alert:
// task.reminder.fired (single task, info), task.overdue (single task, warning),
// and tasks.overdue (a list, one alert per task, warning each). An unrecognized
// event yields no alerts rather than an error, so subscribing beacon to a
// superset of events is harmless.
func (VikunjaAdapter) Adapt(body []byte, r *http.Request) ([]alert.Alert, error) {
	var env vikunjaEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("beacon: vikunja payload: %w", err)
	}
	when := parseVikunjaTime(env.Time)

	switch env.EventName {
	case "task.reminder.fired":
		task, err := vikunjaSingleTask(env.Data)
		if err != nil {
			return nil, err
		}
		return []alert.Alert{vikunjaAlert(env.EventName, "Task reminder", task, courier.LevelInfo, when)}, nil

	case "task.overdue":
		task, err := vikunjaSingleTask(env.Data)
		if err != nil {
			return nil, err
		}
		return []alert.Alert{vikunjaAlert(env.EventName, "Task overdue", task, courier.LevelWarning, when)}, nil

	case "tasks.overdue":
		var d struct {
			Tasks []vikunjaTask `json:"tasks"`
		}
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return nil, fmt.Errorf("beacon: vikunja tasks.overdue data: %w", err)
		}
		out := make([]alert.Alert, 0, len(d.Tasks))
		for _, task := range d.Tasks {
			out = append(out, vikunjaAlert(env.EventName, "Task overdue", task, courier.LevelWarning, when))
		}
		return out, nil

	default:
		return nil, nil
	}
}

// vikunjaSingleTask extracts the single task from a {task: {...}} data object.
func vikunjaSingleTask(data json.RawMessage) (vikunjaTask, error) {
	var d struct {
		Task vikunjaTask `json:"task"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return vikunjaTask{}, fmt.Errorf("beacon: vikunja task data: %w", err)
	}
	return d.Task, nil
}

// vikunjaAlert builds one native alert for a task. The title is
// "<phrase>: <identifier> <title>", with the identifier (and its trailing space)
// omitted when empty; the body carries the due date when set and is empty when
// the due date is the zero value.
func vikunjaAlert(eventName, phrase string, t vikunjaTask, level courier.Level, when time.Time) alert.Alert {
	title := phrase + ": "
	if t.Identifier != "" {
		title += t.Identifier + " "
	}
	title += t.Title

	body := ""
	if !t.DueDate.IsZero() {
		body = "Due: " + t.DueDate.Format(time.RFC3339)
	}

	return alert.Alert{
		DedupKey: "vikunja|" + strconv.FormatInt(t.ID, 10),
		Source:   alert.SourceIngest,
		Adapter:  "vikunja",
		Event:    "vikunja",
		Time:     when,
		Notification: courier.Notification{
			Title: title,
			Body:  body,
			Level: level,
			Fields: map[string]string{
				"source":     "vikunja",
				"event_name": eventName,
			},
		},
	}
}

// parseVikunjaTime parses the envelope's RFC3339 time, falling back to now when
// it is absent or unparseable.
func parseVikunjaTime(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Now()
}
