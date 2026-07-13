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
	ownerUserID string,
	value shortlink.Link,
	now time.Time,
) (shortlink.Link, error) {
	id, err := randomID()
	if err != nil {
		return shortlink.Link{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return shortlink.Link{}, fmt.Errorf("begin short-link creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO short_links (
			id, owner_user_id, slug, title, description, mode, enabled,
			created_at, updated_at, expires_at
		)
		SELECT ?, u.id, ?, ?, ?, ?, 1, ?, ?, ?
		FROM users AS u
		WHERE u.id = ? AND u.status = ?
		ON CONFLICT(slug) DO NOTHING`,
		id, value.Slug, value.Title, value.Description, value.Mode,
		unix(now), unix(now), nullableUnix(value.ExpiresAt), ownerUserID, auth.UserActive,
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
		if err := tx.QueryRowContext(ctx,
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
	destinations, err := insertDestinations(ctx, tx, id, value.Destinations)
	if err != nil {
		return shortlink.Link{}, err
	}
	if err := tx.Commit(); err != nil {
		return shortlink.Link{}, fmt.Errorf("commit short-link creation: %w", err)
	}
	value.ID = id
	value.OwnerUserID = ownerUserID
	value.Destinations = destinations
	value.Enabled = true
	value.CreatedAt = now.UTC()
	value.UpdatedAt = now.UTC()
	return value, nil
}

func (s *SQLite) ShortLinks(ctx context.Context, ownerUserID string, includeAll bool) ([]shortlink.Link, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin managed short-link snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT l.id, l.owner_user_id, u.username, l.slug, l.title,
		       l.description, l.mode, l.enabled, l.created_at, l.updated_at,
		       l.expires_at, COALESCE(SUM(ds.visits), 0),
		       MAX(ds.last_visited_at)
		FROM short_links AS l
		JOIN users AS u ON u.id = l.owner_user_id
		LEFT JOIN short_link_daily_stats AS ds ON ds.link_id = l.id
		WHERE l.deleted_at IS NULL AND (l.owner_user_id = ? OR ? = 1)
		GROUP BY l.id
		ORDER BY l.created_at DESC, l.id DESC`, ownerUserID, includeAll)
	if err != nil {
		return nil, fmt.Errorf("query short links: %w", err)
	}
	links := make([]shortlink.Link, 0)
	byID := make(map[string]int)
	for rows.Next() {
		link, err := scanManagedShortLink(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		links = append(links, link)
		byID[link.ID] = len(links) - 1
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate short links: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close short-link rows: %w", err)
	}

	destinations, err := tx.QueryContext(ctx, `
		SELECT d.id, d.link_id, d.label, d.target_url, d.position
		FROM short_link_destinations AS d
		JOIN short_links AS l ON l.id = d.link_id
		WHERE l.deleted_at IS NULL AND (l.owner_user_id = ? OR ? = 1)
		ORDER BY d.link_id, d.position`, ownerUserID, includeAll)
	if err != nil {
		return nil, fmt.Errorf("query managed short-link destinations: %w", err)
	}
	for destinations.Next() {
		var destination shortlink.Destination
		var linkID string
		if err := destinations.Scan(
			&destination.ID, &linkID, &destination.Label,
			&destination.URL, &destination.Position,
		); err != nil {
			_ = destinations.Close()
			return nil, fmt.Errorf("scan managed short-link destination: %w", err)
		}
		if index, exists := byID[linkID]; exists {
			links[index].Destinations = append(links[index].Destinations, destination)
		}
	}
	if err := destinations.Err(); err != nil {
		_ = destinations.Close()
		return nil, fmt.Errorf("iterate managed short-link destinations: %w", err)
	}
	if err := destinations.Close(); err != nil {
		return nil, fmt.Errorf("close managed short-link destinations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit managed short-link snapshot: %w", err)
	}
	return links, nil
}

func (s *SQLite) UpdateShortLink(
	ctx context.Context,
	id, actorUserID string,
	includeAll bool,
	input shortlink.Input,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin short-link update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ownerUserID, slug, err := updateLinkDetails(
		ctx, tx, id, actorUserID, includeAll, input, now,
	)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM short_link_destinations WHERE link_id = ?`, id); err != nil {
		return fmt.Errorf("replace short-link destinations: %w", err)
	}
	if _, err := insertDestinations(ctx, tx, id, input.Destinations); err != nil {
		return err
	}
	if err := recordCrossOwnerAudit(ctx, tx, actorUserID, ownerUserID, id, slug, shortlink.AuditUpdated, includeAll, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit short-link update: %w", err)
	}
	return nil
}

func (s *SQLite) SetShortLinkEnabled(
	ctx context.Context,
	id, actorUserID string,
	includeAll, enabled bool,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin short-link state change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ownerUserID, slug string
	err = tx.QueryRowContext(ctx, `
		UPDATE short_links
		SET enabled = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
		  AND (owner_user_id = ? OR ? = 1)
		RETURNING owner_user_id, slug`,
		enabled, unix(now), id, actorUserID, includeAll,
	).Scan(&ownerUserID, &slug)
	if errors.Is(err, sql.ErrNoRows) {
		return shortlink.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("update short-link state: %w", err)
	}
	kind := shortlink.AuditDisabled
	if enabled {
		kind = shortlink.AuditEnabled
	}
	if err := recordCrossOwnerAudit(ctx, tx, actorUserID, ownerUserID, id, slug, kind, includeAll, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit short-link state change: %w", err)
	}
	return nil
}

func (s *SQLite) RetireShortLink(
	ctx context.Context,
	id, actorUserID string,
	includeAll bool,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin short-link retirement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ownerUserID, slug string
	err = tx.QueryRowContext(ctx, `
		UPDATE short_links
		SET enabled = 0, updated_at = ?, deleted_at = ?
		WHERE id = ? AND deleted_at IS NULL
		  AND (owner_user_id = ? OR ? = 1)
		RETURNING owner_user_id, slug`,
		unix(now), unix(now), id, actorUserID, includeAll,
	).Scan(&ownerUserID, &slug)
	if errors.Is(err, sql.ErrNoRows) {
		return shortlink.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("retire short link: %w", err)
	}
	if err := recordCrossOwnerAudit(ctx, tx, actorUserID, ownerUserID, id, slug, shortlink.AuditRetired, includeAll, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit short-link retirement: %w", err)
	}
	return nil
}

func (s *SQLite) ResolveShortLink(ctx context.Context, slug string, now time.Time) (shortlink.Link, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT l.id, l.owner_user_id, l.slug, l.mode, l.enabled,
		       l.created_at, l.updated_at, l.expires_at,
		       d.id, d.label, d.target_url, d.position
		FROM short_links AS l
		JOIN short_link_destinations AS d ON d.link_id = l.id
		WHERE l.slug = ? AND l.enabled = 1 AND l.deleted_at IS NULL
		  AND (l.expires_at IS NULL OR l.expires_at > ?)
		ORDER BY d.position`, slug, unix(now))
	if err != nil {
		return shortlink.Link{}, fmt.Errorf("resolve short link: %w", err)
	}
	defer rows.Close()
	var link shortlink.Link
	found := false
	for rows.Next() {
		var linkID, ownerUserID, storedSlug string
		var mode shortlink.Mode
		var enabled bool
		var createdAt, updatedAt int64
		var expiresAt sql.NullInt64
		var destination shortlink.Destination
		if err := rows.Scan(
			&linkID, &ownerUserID, &storedSlug, &mode, &enabled,
			&createdAt, &updatedAt, &expiresAt,
			&destination.ID, &destination.Label, &destination.URL, &destination.Position,
		); err != nil {
			return shortlink.Link{}, fmt.Errorf("scan resolved short link: %w", err)
		}
		if !found {
			link.ID = linkID
			link.OwnerUserID = ownerUserID
			link.Slug = storedSlug
			link.Mode = mode
			link.Enabled = enabled
			link.CreatedAt = time.Unix(createdAt, 0).UTC()
			link.UpdatedAt = time.Unix(updatedAt, 0).UTC()
			if expiresAt.Valid {
				link.ExpiresAt = time.Unix(expiresAt.Int64, 0).UTC()
			}
			found = true
		}
		link.Destinations = append(link.Destinations, destination)
	}
	if err := rows.Err(); err != nil {
		return shortlink.Link{}, fmt.Errorf("iterate resolved short link: %w", err)
	}
	if !found {
		return shortlink.Link{}, shortlink.ErrNotFound
	}
	return link, nil
}

func (s *SQLite) AddShortLinkVisits(ctx context.Context, buckets []shortlink.VisitBucket) error {
	if len(buckets) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin short-link visit flush: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, bucket := range buckets {
		if bucket.Visits <= 0 || bucket.LinkID == "" || bucket.Day.IsZero() || bucket.LastVisitedAt.IsZero() {
			return errors.New("invalid short-link visit bucket")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO short_link_daily_stats (link_id, day, visits, last_visited_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(link_id, day) DO UPDATE SET
				visits = visits + excluded.visits,
				last_visited_at = max(last_visited_at, excluded.last_visited_at)`,
			bucket.LinkID, unix(bucket.Day), bucket.Visits, unix(bucket.LastVisitedAt),
		); err != nil {
			return fmt.Errorf("upsert short-link visit bucket: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit short-link visit flush: %w", err)
	}
	return nil
}

func (s *SQLite) ShortLinkDailyStats(
	ctx context.Context,
	ownerUserID string,
	includeAll bool,
	since time.Time,
) ([]shortlink.DailyStat, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ds.link_id, ds.day, ds.visits, ds.last_visited_at
		FROM short_link_daily_stats AS ds
		JOIN short_links AS l ON l.id = ds.link_id
		WHERE l.deleted_at IS NULL AND ds.day >= ?
		  AND (l.owner_user_id = ? OR ? = 1)
		ORDER BY ds.day DESC, ds.link_id`, unix(since), ownerUserID, includeAll)
	if err != nil {
		return nil, fmt.Errorf("query short-link daily stats: %w", err)
	}
	defer rows.Close()
	var stats []shortlink.DailyStat
	for rows.Next() {
		var stat shortlink.DailyStat
		var day, lastVisitedAt int64
		if err := rows.Scan(&stat.LinkID, &day, &stat.Visits, &lastVisitedAt); err != nil {
			return nil, fmt.Errorf("scan short-link daily stat: %w", err)
		}
		stat.Day = time.Unix(day, 0).UTC()
		stat.LastVisitedAt = time.Unix(lastVisitedAt, 0).UTC()
		stats = append(stats, stat)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate short-link daily stats: %w", err)
	}
	return stats, nil
}

func (s *SQLite) ShortLinkAuditEvents(
	ctx context.Context,
	ownerUserID string,
	includeAll bool,
	limit int,
) ([]shortlink.AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.occurred_at, actor.username, owner.username, e.slug, e.kind
		FROM short_link_audit_events AS e
		JOIN users AS actor ON actor.id = e.actor_user_id
		JOIN users AS owner ON owner.id = e.owner_user_id
		WHERE e.owner_user_id = ? OR ? = 1
		ORDER BY e.occurred_at DESC, e.id DESC
		LIMIT ?`, ownerUserID, includeAll, limit)
	if err != nil {
		return nil, fmt.Errorf("query short-link audit events: %w", err)
	}
	defer rows.Close()
	var events []shortlink.AuditEvent
	for rows.Next() {
		var event shortlink.AuditEvent
		var occurredAt int64
		if err := rows.Scan(
			&occurredAt, &event.ActorUsername, &event.OwnerUsername,
			&event.Slug, &event.Kind,
		); err != nil {
			return nil, fmt.Errorf("scan short-link audit event: %w", err)
		}
		event.OccurredAt = time.Unix(occurredAt, 0).UTC()
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate short-link audit events: %w", err)
	}
	return events, nil
}

func updateLinkDetails(
	ctx context.Context,
	tx *sql.Tx,
	id, actorUserID string,
	includeAll bool,
	input shortlink.Input,
	now time.Time,
) (string, string, error) {
	var ownerUserID, slug string
	err := tx.QueryRowContext(ctx, `
		UPDATE short_links
		SET title = ?, description = ?, mode = ?, expires_at = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL
		  AND (owner_user_id = ? OR ? = 1)
		RETURNING owner_user_id, slug`,
		input.Title, input.Description, input.Mode, nullableUnix(input.ExpiresAt),
		unix(now), id, actorUserID, includeAll,
	).Scan(&ownerUserID, &slug)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", shortlink.ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("update short-link details: %w", err)
	}
	return ownerUserID, slug, nil
}

func insertDestinations(
	ctx context.Context,
	tx *sql.Tx,
	linkID string,
	values []shortlink.Destination,
) ([]shortlink.Destination, error) {
	result := make([]shortlink.Destination, 0, len(values))
	for position, value := range values {
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO short_link_destinations (
				id, link_id, position, label, target_url
			) VALUES (?, ?, ?, ?, ?)`,
			id, linkID, position, value.Label, value.URL,
		); err != nil {
			return nil, fmt.Errorf("insert short-link destination: %w", err)
		}
		value.ID = id
		value.Position = position
		result = append(result, value)
	}
	return result, nil
}

func recordCrossOwnerAudit(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID, ownerUserID, linkID, slug string,
	kind shortlink.AuditKind,
	includeAll bool,
	now time.Time,
) error {
	if actorUserID == ownerUserID {
		return nil
	}
	if !includeAll {
		return shortlink.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO short_link_audit_events (
			occurred_at, actor_user_id, owner_user_id, link_id, slug, kind
		) VALUES (?, ?, ?, ?, ?, ?)`,
		unix(now), actorUserID, ownerUserID, linkID, slug, kind,
	); err != nil {
		return fmt.Errorf("record cross-owner short-link audit: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanManagedShortLink(row rowScanner) (shortlink.Link, error) {
	var link shortlink.Link
	var createdAt, updatedAt int64
	var expiresAt, lastVisitedAt sql.NullInt64
	if err := row.Scan(
		&link.ID, &link.OwnerUserID, &link.OwnerUsername, &link.Slug,
		&link.Title, &link.Description, &link.Mode, &link.Enabled,
		&createdAt, &updatedAt, &expiresAt, &link.VisitCount, &lastVisitedAt,
	); err != nil {
		return shortlink.Link{}, fmt.Errorf("scan short link: %w", err)
	}
	link.CreatedAt = time.Unix(createdAt, 0).UTC()
	link.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if expiresAt.Valid {
		link.ExpiresAt = time.Unix(expiresAt.Int64, 0).UTC()
	}
	if lastVisitedAt.Valid {
		link.LastVisitedAt = time.Unix(lastVisitedAt.Int64, 0).UTC()
	}
	return link, nil
}

func nullableUnix(value time.Time) sql.NullInt64 {
	if value.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: unix(value), Valid: true}
}
