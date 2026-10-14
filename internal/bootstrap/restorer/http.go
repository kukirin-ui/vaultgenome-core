// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package restorer

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// Routes returns the Restorer's read-only endpoints, for the daemon's
// API listener (TLS, and mTLS or bearer beyond loopback):
//
//	GET /v1/genome/restores           — every restore's record
//	GET /v1/genome/receipt?key_id=ID  — a completed restore's signed receipt
//
// With a bearer token set, every request must carry it.
func (r *Restorer) Routes(bearerToken string) map[string]http.HandlerFunc {
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			if bearerToken != "" {
				got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
				if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(bearerToken)) != 1 {
					writeError(w, http.StatusUnauthorized, "bearer token missing or invalid")
					return
				}
			}
			next(w, req)
		}
	}
	return map[string]http.HandlerFunc{
		"/v1/genome/restores": guard(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"restores": r.Records()})
		}),
		"/v1/genome/receipt": guard(func(w http.ResponseWriter, req *http.Request) {
			kid := req.URL.Query().Get("key_id")
			if kid == "" {
				writeError(w, http.StatusBadRequest, "key_id required")
				return
			}
			signed, rec, ok := r.Receipt(kid)
			switch {
			case !ok:
				writeError(w, http.StatusNotFound, "no key "+kid+" was released to this destination")
			case signed.Receipt == nil && rec.State == StateFailed:
				// Final: asking again will not bring a receipt.
				writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "restore failed: " + rec.Error, "restore": rec})
			case signed.Receipt == nil:
				writeJSON(w, http.StatusConflict, map[string]any{"error": "restore not complete", "restore": rec})
			default:
				writeJSON(w, http.StatusOK, signed)
			}
		}),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
