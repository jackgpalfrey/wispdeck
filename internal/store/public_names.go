package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type publicNameClaim int

const (
	publicNameClaimed publicNameClaim = iota
	publicNameReclaimed
	publicNameNeedsConfirmation
	publicNameUnavailable
)

// claimPublicName reserves a new deployment-wide name or atomically transfers
// a retired link name to a fresh resource owned by the same user. Active names,
// site names, and names owned by another user are never reclaimable.
func claimPublicName(
	ctx context.Context,
	tx *sql.Tx,
	name, ownerUserID, kind, resourceID string,
	now time.Time,
	allowReclaim bool,
) (publicNameClaim, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO public_names (
			name, owner_user_id, kind, resource_id, created_at
		) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO NOTHING`,
		name, ownerUserID, kind, resourceID, unix(now),
	)
	if err != nil {
		return publicNameUnavailable, fmt.Errorf("reserve public name: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return publicNameUnavailable, fmt.Errorf("inspect public name reservation: %w", err)
	}
	if rows == 1 {
		return publicNameClaimed, nil
	}

	var existingOwner, existingKind string
	var retiredAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT owner_user_id, kind, retired_at
		FROM public_names
		WHERE name = ?`,
		name,
	).Scan(&existingOwner, &existingKind, &retiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return publicNameUnavailable, fmt.Errorf("public name disappeared during reservation")
	}
	if err != nil {
		return publicNameUnavailable, fmt.Errorf("inspect existing public name: %w", err)
	}
	if existingOwner != ownerUserID || existingKind != "link" || !retiredAt.Valid {
		return publicNameUnavailable, nil
	}
	if !allowReclaim {
		return publicNameNeedsConfirmation, nil
	}

	result, err = tx.ExecContext(ctx, `
		UPDATE public_names
		SET kind = ?, resource_id = ?, created_at = ?, retired_at = NULL
		WHERE name = ?
		  AND owner_user_id = ?
		  AND kind = 'link'
		  AND retired_at IS NOT NULL`,
		kind, resourceID, unix(now), name, ownerUserID,
	)
	if err != nil {
		return publicNameUnavailable, fmt.Errorf("reclaim public name: %w", err)
	}
	rows, err = result.RowsAffected()
	if err != nil {
		return publicNameUnavailable, fmt.Errorf("inspect public name reclamation: %w", err)
	}
	if rows != 1 {
		return publicNameUnavailable, nil
	}
	return publicNameReclaimed, nil
}
