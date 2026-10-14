// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"encoding/json"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// EncodeBody canonical-JSON-encodes a body value. The output is the
// exact byte sequence that will become a frame payload (before any MAC
// is appended by the session layer).
//
// EncodeBody is a thin wrapper over /internal/shared/crypto.CanonicalJSON
// so that every wire encode path goes through the same canonical
// encoder the rest of the codebase uses for contract signatures and
// audit-event hashes. A direct call to encoding/json.Marshal is a bug
// on the wire side and a reviewer-enforced invariant here.
//
// EncodeBody does NOT attach the FrameType discriminator — that is
// the body struct's own job (each body type embeds a `Type string`
// field with a `json:"type"` tag). This keeps the codec trivial and
// the discriminator self-contained in bodies.go.
func EncodeBody(v any) ([]byte, error) {
	b, err := crypto.CanonicalJSON(v)
	if err != nil {
		return nil, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: canonical encode failed",
			err,
		)
	}
	return b, nil
}

// typeProbe is the minimal shape used to extract the `type`
// discriminator before the caller knows which concrete body struct to
// decode into. Decoding a well-formed wire frame into typeProbe
// cannot fail on well-formed input because `type` is a plain string
// and any extra fields are ignored by encoding/json.
type typeProbe struct {
	Type string `json:"type"`
}

// PeekType extracts the `type` discriminator from a canonical-JSON
// body without decoding the rest of the frame. Returns Structural /
// CodeProtocolViolation if the payload is not a JSON object, or if
// the `type` field is missing or empty.
//
// PeekType is used by the frame dispatcher (in conn.go and the
// server/client halves) to pick the right concrete body struct
// before calling DecodeBody.
func PeekType(payload []byte) (string, error) {
	var t typeProbe
	if err := json.Unmarshal(payload, &t); err != nil {
		return "", shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: payload is not canonical JSON or not an object",
			err,
		)
	}
	if t.Type == "" {
		return "", shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: frame body missing mandatory type field",
			nil,
		)
	}
	return t.Type, nil
}

// DecodeBody decodes a canonical-JSON payload into dst. dst must be a
// non-nil pointer to a concrete body struct whose `Type` field's
// expected value is known to the caller (typically because PeekType
// has already been called).
//
// DecodeBody does NOT cross-check dst's Type field against the payload
// — callers are expected to have already dispatched on the type
// discriminator. This keeps the codec single-purpose and avoids a
// hidden second parse of the payload.
//
// Any structural error (malformed JSON, wrong shape, missing required
// field on a schema-versioned body) is surfaced as Structural /
// CodeProtocolViolation. The inner error is attached for diagnostics
// but MUST NOT be included in any ErrorEnvelope put on the wire —
// callers wrap DecodeBody's error with NewErrorEnvelope, which trims
// the message to 1024 bytes and does not leak nested encoding/json
// error text verbatim.
func DecodeBody(payload []byte, dst any) error {
	if dst == nil {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: DecodeBody called with nil destination",
			nil,
		)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: canonical-JSON decode into body failed",
			err,
		)
	}
	return nil
}
