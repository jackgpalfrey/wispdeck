package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/shortlink"
)

func (s *SQLite) CreateShortLink(
	ctx context.Context,
	ownerUserID, slug, targetURL string,
	now time.Time,
) (shortlink.Link, error) {
	id, err := randomID()
	if err != nil {
		return shortlink.Link{}, err
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO short_links (
			id, owner_user_id, slug, target_url, enabled, visit_count,
			created_at, updated_at
		)
		SELECT ?, u.id, ?, ?, 1, 0, ?, ?
		FROM users AS u
		WHERE u.id = ? AND u.status = ?
		ON CONFLICT(slug) DO NOTHING`,
		id, slug, targetURL, unix(now), unix(now), ownerUserID, auth.UserActive,
	)
	if err != nil {
		return shortlink.Link{}, fmt.Errorf("insert short link: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return shortlink.Link{}, fmt.Errorf("inspect short-link insert: %w", err)
	}
	if rows != 1 {
		var active bool
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND status = ?)`,
			ownerUserID, auth.UserActive,
		).Scan(&active); err != nil {
			return shortlink.Link{}, fmt.Errorf("check short-link owner: %w", err)
		}
		if !active {
			return shortlink.Link{}, shortlink.ErrForbidden
		}
		return shortlink.Link{}, shortlink.ErrSlugUnavailable
	}
	return shortlink.Link{
		ID: id, OwnerUserID: ownerUserID, Slug: slug, TargetURL: targetURL,
		Enabled: true, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (s *SQLite) ShortLinks(ctx context.Context, ownerUserID string, includeAll bool) ([]shortlink.Link, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.id, l.owner_user_id, u.username, l.slug, l.target_url,
		       l.enabled, l.visit_count, l.created_at, l.updated_at,
		       l.last_visited_at
		FROM short_links AS l
		JOIN users AS u ON u.id = l.owner_user_id
		WHERE l.deleted_at IS NULL AND (l.owner_user_id = ? OR ? = 1)
		ORDER BY l.created_at DESC, l.id DESC`, ownerUserID, includeAll)
	if err != nil {
		return nil, fmt.Errorf("query short links: %w", err)
	}
	defer rows.Close()

	links := make([]shortlink.Link, 0)
	for rows.Next() {
		link, err := scanShortLink(rows)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate short links: %w", err)
	}
	return links, nil
}

func (s *SQLite) UpdateShortLinkTarget(
	ctx context.Context,
	id, ownerUserID string,
	includeAll bool,
	targetURL string,
	now time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE short_links
		SET target_url = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL AND (owner_user_id = ? OR ? = 1)`,
		targetURL, unix(now), id, ownerUserID, includeAll,
	)
	if err != nil {
		return fmt.Errorf("update short-link target: %w", err)
	}
	return requireShortLink(result)
}

func (s *SQLite) SetShortLinkEnabled(
	ctx context.Context,
	id, ownerUserID string,
	includeAll, enabled bool,
	now time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE short_links
		SET enabled = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL AND (owner_user_id = ? OR ? = 1)`,
		enabled, unix(now), id, ownerUserID, includeAll,
	)
	if err != nil {
		return fmt.Errorf("update short-link state: %w", err)
	}
	return requireShortLink(result)
}

func (s *SQLite) RetireShortLink(
	ctx context.Context,
	id, ownerUserID string,
	includeAll bool,
	now time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE short_links
		SET enabled = 0, updated_at = ?, deleted_at = ?
		WHERE id = ? AND deleted_at IS NULL AND (owner_user_id = ? OR ? = 1)`,
		unix(now), unix(now), id, ownerUserID, includeAll,
	)
	if err != nil {
		return fmt.Errorf("retire short link: %w", err)
	}
	return requireShortLink(result)
}

func (s *SQLite) ResolveShortLink(ctx context.Context, slug string, now time.Time) (shortlink.Link, error) {
	var link shortlink.Link
	var createdAt, updatedAt, lastVisitedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
		UPDATE short_links
		SET visit_count = visit_count + 1, last_visited_at = ?
		WHERE slug = ? AND enabled = 1 AND deleted_at IS NULL
		RETURNING id, owner_user_id, slug, target_url, enabled, visit_count,
		          created_at, updated_at, last_visited_at`, unix(now), slug,
	).Scan(
		&link.ID, &link.OwnerUserID, &link.Slug, &link.TargetURL,
		&link.Enabled, &link.VisitCount, &createdAt, &updatedAt, &lastVisitedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return shortlink.Link{}, shortlink.ErrNotFound
	}
	if err != nil {
		return shortlink.Link{}, fmt.Errorf("resolve short link: %w", err)
	}
	setShortLinkTimes(&link, createdAt, updatedAt, lastVisitedAt)
	return link, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanShortLink(row rowScanner) (shortlink.Link, error) {
	var link shortlink.Link
	var createdAt, updatedAt, lastVisitedAt sql.NullInt64
	if err := row.Scan(
		&link.ID, &link.OwnerUserID, &link.OwnerUsername, &link.Slug,
		&link.TargetURL, &link.Enabled, &link.VisitCount, &createdAt,
		&updatedAt, &lastVisitedAt,
	); err != nil {
		return shortlink.Link{}, fmt.Errorf("scan short link: %w", err)
	}
	setShortLinkTimes(&link, createdAt, updatedAt, lastVisitedAt)
	return link, nil
}

func setShortLinkTimes(link *shortlink.Link, createdAt, updatedAt, lastVisitedAt sql.NullInt64) {
	if createdAt.Valid {
		link.CreatedAt = time.Unix(createdAt.Int64, 0).UTC()
	}
	if updatedAt.Valid {
		link.UpdatedAt = time.Unix(updatedAt.Int64, 0).UTC()
	}
	if lastVisitedAt.Valid {
		link.LastVisitedAt = time.Unix(lastVisitedAt.Int64, 0).UTC()
	}
}

func requireShortLink(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect short-link mutation: %w", err)
	}
	if rows != 1 {
		return shortlink.ErrNotFound
	}
	return nil
}
