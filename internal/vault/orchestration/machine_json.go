// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package orchestration

import (
	"encoding/json"
	"fmt"
	"time"
)

// marshalJSON is encoding/json, kept behind one name so the package's
// JSON surface is easy to find.
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// MarshalText renders a State by its name, so it reads in JSON views.
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a State from its name, so a JSON view reads back.
func (s *State) UnmarshalText(b []byte) error {
	name := string(b)
	for candidate := StateUnstarted; candidate <= StateCrossCloudHandshake; candidate++ {
		if candidate.String() == name {
			*s = candidate
			return nil
		}
	}
	return fmt.Errorf("orchestration: unknown state %q", name)
}

// UnmarshalJSON parses a Step by its state names.
func (s *Step) UnmarshalJSON(b []byte) error {
	var wire struct {
		From    State     `json:"from"`
		To      State     `json:"to"`
		Trigger string    `json:"trigger"`
		At      time.Time `json:"at"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	*s = Step{From: wire.From, To: wire.To, Trigger: wire.Trigger, At: wire.At}
	return nil
}
