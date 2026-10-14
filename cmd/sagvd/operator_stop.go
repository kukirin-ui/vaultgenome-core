// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"sync"

	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// newOperatorStopSource reads and verifies the operator's stop list once
// (a daemon does not start on a list it cannot verify) and returns a
// source that reads it again at every trust admission, so the operator
// stops the daemon's releases by writing a new list. A list with a
// serial older than one already consulted is refused: an operator stop
// cannot be rolled back by restoring an old file.
func newOperatorStopSource(cfg OperatorStopConfig) (trust.StopListSource, uint64, error) {
	first, err := loadOperatorStop(cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("sagvd: operator_stop: %w", err)
	}
	var mu sync.Mutex
	highest := first.Serial
	return func() (revocation.List, error) {
		list, err := loadOperatorStop(cfg)
		if err != nil {
			return revocation.List{}, err
		}
		mu.Lock()
		defer mu.Unlock()
		if list.Serial < highest {
			return revocation.List{}, fmt.Errorf("revocation: list serial %d is older than serial %d already consulted (rollback refused)", list.Serial, highest)
		}
		highest = list.Serial
		return list, nil
	}, first.Serial, nil
}
