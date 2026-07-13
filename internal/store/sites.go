package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wispdeck/wispdeck/internal/auth"
	"github.com/wispdeck/wispdeck/internal/site"
)

func (s *SQLite) CreateSite(
	ctx context.Context,
	ownerUserID, name, title string,
	now time.Time,
) (site.Site, error) {
	id, err := randomID()
	if err != nil {
		return site.Site{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return site.Site{}, fmt.Errorf("begin site creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO public_names (
			name, owner_user_id, kind, resource_id, created_at
		)
		SELECT ?, u.id, 'site', ?, ?
		FROM users AS u
		WHERE u.id = ? AND u.status = ?
		ON CONFLICT(name) DO NOTHING`,
		name, id, unix(now), ownerUserID, auth.UserActive,
	)
	if err != nil {
		return site.Site{}, fmt.Errorf("reserve site name: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return site.Site{}, fmt.Errorf("inspect site name reservation: %w", err)
	}
	if rows != 1 {
		var active bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND status = ?)`,
			ownerUserID, auth.UserActive,
		).Scan(&active); err != nil {
			return site.Site{}, fmt.Errorf("check site owner: %w", err)
		}
		if !active {
			return site.Site{}, site.ErrForbidden
		}
		return site.Site{}, site.ErrNameUnavailable
	}
	result, err = tx.ExecContext(ctx, `
		INSERT INTO sites (
			id, owner_user_id, name, title, enabled, created_at, updated_at
		) VALUES (?, ?, ?, ?, 1, ?, ?)`,
		id, ownerUserID, name, title, unix(now), unix(now),
	)
	if err != nil {
		return site.Site{}, fmt.Errorf("insert site: %w", err)
	}
	if err := requireOneRow(result, "site"); err != nil {
		return site.Site{}, err
	}
	if err := tx.Commit(); err != nil {
		return site.Site{}, fmt.Errorf("commit site creation: %w", err)
	}
	return site.Site{
		ID: id, OwnerUserID: ownerUserID, Name: name, Title: title,
		Enabled: true, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func (s *SQLite) Sites(ctx context.Context, ownerUserID string, includeAll bool) ([]site.Site, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin managed site snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT s.id, s.owner_user_id, u.username, s.name, s.title, s.enabled,
		       s.created_at, s.updated_at, s.draft_release_id, s.published_release_id
		FROM sites AS s
		JOIN users AS u ON u.id = s.owner_user_id
		WHERE s.owner_user_id = ? OR ? = 1
		ORDER BY s.created_at DESC, s.id DESC`, ownerUserID, includeAll)
	if err != nil {
		return nil, fmt.Errorf("query managed sites: %w", err)
	}
	var sites []site.Site
	byID := make(map[string]int)
	for rows.Next() {
		value, err := scanSite(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		sites = append(sites, value)
		byID[value.ID] = len(sites) - 1
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate managed sites: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close managed sites: %w", err)
	}

	releaseRows, err := tx.QueryContext(ctx, `
		SELECT r.id, r.site_id, r.version, r.file_count, r.total_bytes,
		       r.bundle_digest, r.created_at, r.published_at
		FROM site_releases AS r
		JOIN sites AS s ON s.id = r.site_id
		WHERE s.owner_user_id = ? OR ? = 1
		ORDER BY r.site_id, r.version DESC`, ownerUserID, includeAll)
	if err != nil {
		return nil, fmt.Errorf("query managed site releases: %w", err)
	}
	for releaseRows.Next() {
		release, err := scanRelease(releaseRows)
		if err != nil {
			_ = releaseRows.Close()
			return nil, err
		}
		if index, exists := byID[release.SiteID]; exists {
			sites[index].Releases = append(sites[index].Releases, release)
		}
	}
	if err := releaseRows.Err(); err != nil {
		_ = releaseRows.Close()
		return nil, fmt.Errorf("iterate managed site releases: %w", err)
	}
	if err := releaseRows.Close(); err != nil {
		return nil, fmt.Errorf("close managed site releases: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit managed site snapshot: %w", err)
	}
	return sites, nil
}

func (s *SQLite) CreateSiteRelease(
	ctx context.Context,
	actorUserID string,
	includeAll bool,
	siteID string,
	bundle site.Bundle,
	now time.Time,
) (site.Release, error) {
	releaseID, err := randomID()
	if err != nil {
		return site.Release{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return site.Release{}, fmt.Errorf("begin site release upload: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ownerUserID, name string
	var version int
	err = tx.QueryRowContext(ctx, `
		SELECT s.owner_user_id, s.name, COALESCE(MAX(r.version), 0) + 1
		FROM sites AS s
		LEFT JOIN site_releases AS r ON r.site_id = s.id
		WHERE s.id = ? AND (s.owner_user_id = ? OR ? = 1)
		GROUP BY s.id`, siteID, actorUserID, includeAll,
	).Scan(&ownerUserID, &name, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return site.Release{}, site.ErrNotFound
	}
	if err != nil {
		return site.Release{}, fmt.Errorf("select site for release upload: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO site_releases (
			id, site_id, version, created_by_user_id, file_count,
			total_bytes, bundle_digest, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		releaseID, siteID, version, actorUserID, len(bundle.Files),
		bundle.TotalBytes, bundle.Digest[:], unix(now),
	)
	if err != nil {
		return site.Release{}, fmt.Errorf("insert site release: %w", err)
	}
	if err := requireOneRow(result, "site release"); err != nil {
		return site.Release{}, err
	}
	for _, file := range bundle.Files {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO site_files (release_id, path, content_type, body, digest)
			VALUES (?, ?, ?, ?, ?)`,
			releaseID, file.Path, file.ContentType, file.Body, file.Digest[:],
		); err != nil {
			return site.Release{}, fmt.Errorf("insert site release file %q: %w", file.Path, err)
		}
	}
	result, err = tx.ExecContext(ctx, `
		UPDATE sites SET draft_release_id = ?, updated_at = ? WHERE id = ?`,
		releaseID, unix(now), siteID,
	)
	if err != nil {
		return site.Release{}, fmt.Errorf("select uploaded site draft: %w", err)
	}
	if err := requireOneRow(result, "site draft"); err != nil {
		return site.Release{}, err
	}
	if err := recordCrossOwnerSiteAudit(ctx, tx, actorUserID, ownerUserID, siteID, name, "uploaded", includeAll, now); err != nil {
		return site.Release{}, err
	}
	if err := tx.Commit(); err != nil {
		return site.Release{}, fmt.Errorf("commit site release upload: %w", err)
	}
	return site.Release{
		ID: releaseID, SiteID: siteID, Version: version,
		FileCount: len(bundle.Files), TotalBytes: bundle.TotalBytes,
		Digest: bundle.Digest, CreatedAt: now.UTC(),
	}, nil
}

func (s *SQLite) PublishSiteRelease(
	ctx context.Context,
	actorUserID string,
	includeAll bool,
	siteID, releaseID string,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin site release publication: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ownerUserID, name string
	err = tx.QueryRowContext(ctx, `
		UPDATE sites
		SET published_release_id = ?,
		    draft_release_id = CASE WHEN draft_release_id = ? THEN NULL ELSE draft_release_id END,
		    updated_at = ?
		WHERE id = ? AND (owner_user_id = ? OR ? = 1)
		  AND EXISTS (
			SELECT 1 FROM site_releases WHERE id = ? AND site_id = sites.id
		  )
		RETURNING owner_user_id, name`,
		releaseID, releaseID, unix(now), siteID, actorUserID, includeAll, releaseID,
	).Scan(&ownerUserID, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return site.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("publish site release: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE site_releases SET published_at = COALESCE(published_at, ?)
		WHERE id = ?`, unix(now), releaseID,
	); err != nil {
		return fmt.Errorf("mark site release published: %w", err)
	}
	if err := recordCrossOwnerSiteAudit(ctx, tx, actorUserID, ownerUserID, siteID, name, "published", includeAll, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit site release publication: %w", err)
	}
	return nil
}

func (s *SQLite) SetSiteEnabled(
	ctx context.Context,
	actorUserID string,
	includeAll bool,
	siteID string,
	enabled bool,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin site state change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var ownerUserID, name string
	err = tx.QueryRowContext(ctx, `
		UPDATE sites SET enabled = ?, updated_at = ?
		WHERE id = ? AND (owner_user_id = ? OR ? = 1)
		RETURNING owner_user_id, name`,
		enabled, unix(now), siteID, actorUserID, includeAll,
	).Scan(&ownerUserID, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return site.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("update site state: %w", err)
	}
	kind := "disabled"
	if enabled {
		kind = "enabled"
	}
	if err := recordCrossOwnerSiteAudit(ctx, tx, actorUserID, ownerUserID, siteID, name, kind, includeAll, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit site state change: %w", err)
	}
	return nil
}

func (s *SQLite) SiteByName(ctx context.Context, name string) (site.Site, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.owner_user_id, u.username, s.name, s.title, s.enabled,
		       s.created_at, s.updated_at, s.draft_release_id, s.published_release_id
		FROM sites AS s
		JOIN users AS u ON u.id = s.owner_user_id
		JOIN public_names AS n ON n.kind = 'site' AND n.resource_id = s.id
		WHERE n.name = ? AND n.retired_at IS NULL`, name)
	value, err := scanSite(row)
	if errors.Is(err, sql.ErrNoRows) {
		return site.Site{}, site.ErrNotFound
	}
	return value, err
}

func (s *SQLite) SiteFile(ctx context.Context, releaseID, filePath string) (site.File, error) {
	var file site.File
	var digest []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT path, content_type, body, digest
		FROM site_files WHERE release_id = ? AND path = ?`, releaseID, filePath,
	).Scan(&file.Path, &file.ContentType, &file.Body, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return site.File{}, site.ErrNotFound
	}
	if err != nil {
		return site.File{}, fmt.Errorf("query site file: %w", err)
	}
	if len(digest) != len(file.Digest) {
		return site.File{}, errors.New("stored site file digest has invalid length")
	}
	copy(file.Digest[:], digest)
	return file, nil
}

func (s *SQLite) CreateSitePreviewGrant(
	ctx context.Context,
	actorUserID string,
	includeAll bool,
	name, originLabel string,
	tokenHash [32]byte,
	expiresAt, now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin site preview grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM site_preview_grants WHERE expires_at <= ?`, unix(now)); err != nil {
		return fmt.Errorf("expire site preview grants: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO site_preview_grants (
			token_hash, origin_label, site_id, user_id, created_at, expires_at
		)
		SELECT ?, ?, s.id, ?, ?, ?
		FROM sites AS s
		WHERE s.name = ? AND s.draft_release_id IS NOT NULL
		  AND (s.owner_user_id = ? OR ? = 1)
		  AND NOT EXISTS (
			SELECT 1 FROM site_preview_sessions WHERE origin_label = ?
		  )`,
		tokenHash[:], originLabel, actorUserID, unix(now), unix(expiresAt),
		name, actorUserID, includeAll,
		originLabel,
	)
	if err != nil {
		return fmt.Errorf("insert site preview grant: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect site preview grant: %w", err)
	}
	if rows != 1 {
		var authorized, hasDraft bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM sites
				WHERE name = ? AND (owner_user_id = ? OR ? = 1)
			), EXISTS(
				SELECT 1 FROM sites
				WHERE name = ? AND draft_release_id IS NOT NULL
				  AND (owner_user_id = ? OR ? = 1)
			)`, name, actorUserID, includeAll, name, actorUserID, includeAll,
		).Scan(&authorized, &hasDraft)
		if err != nil {
			return fmt.Errorf("inspect site preview eligibility: %w", err)
		}
		if !authorized {
			return site.ErrNotFound
		}
		if !hasDraft {
			return site.ErrNoDraft
		}
		return errors.New("site preview grant was not inserted")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit site preview grant: %w", err)
	}
	return nil
}

func (s *SQLite) ExchangeSitePreviewGrant(
	ctx context.Context,
	originLabel string,
	grantHash, sessionHash [32]byte,
	expiresAt, now time.Time,
) (site.Preview, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return site.Preview{}, fmt.Errorf("begin site preview exchange: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var value site.Site
	var draftID, publishedID sql.NullString
	var createdAt, updatedAt int64
	var userID string
	err = tx.QueryRowContext(ctx, `
		SELECT s.id, s.owner_user_id, u.username, s.name, s.title, s.enabled,
		       s.created_at, s.updated_at, s.draft_release_id, s.published_release_id,
		       g.user_id
		FROM site_preview_grants AS g
		JOIN sites AS s ON s.id = g.site_id
		JOIN users AS u ON u.id = s.owner_user_id
		JOIN users AS viewer ON viewer.id = g.user_id
		WHERE g.token_hash = ? AND g.origin_label = ? AND g.expires_at > ?
		  AND s.draft_release_id IS NOT NULL AND viewer.status = ?`,
		grantHash[:], originLabel, unix(now), auth.UserActive,
	).Scan(
		&value.ID, &value.OwnerUserID, &value.OwnerUsername, &value.Name,
		&value.Title, &value.Enabled, &createdAt, &updatedAt,
		&draftID, &publishedID, &userID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return site.Preview{}, site.ErrInvalidPreview
	}
	if err != nil {
		return site.Preview{}, fmt.Errorf("consume site preview grant: %w", err)
	}
	value.CreatedAt = time.Unix(createdAt, 0).UTC()
	value.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	value.DraftReleaseID = draftID.String
	value.PublishedReleaseID = publishedID.String
	result, err := tx.ExecContext(ctx, `DELETE FROM site_preview_grants WHERE token_hash = ?`, grantHash[:])
	if err != nil {
		return site.Preview{}, fmt.Errorf("delete consumed site preview grant: %w", err)
	}
	if err := requireOneRow(result, "site preview grant"); err != nil {
		return site.Preview{}, site.ErrInvalidPreview
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM site_preview_sessions WHERE expires_at <= ?`, unix(now)); err != nil {
		return site.Preview{}, fmt.Errorf("expire site preview sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO site_preview_sessions (
			token_hash, origin_label, site_id, user_id, created_at, expires_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		sessionHash[:], originLabel, value.ID, userID, unix(now), unix(expiresAt),
	); err != nil {
		return site.Preview{}, fmt.Errorf("insert site preview session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return site.Preview{}, fmt.Errorf("commit site preview exchange: %w", err)
	}
	return site.Preview{
		Site: value, DraftReleaseID: draftID.String,
		PublishedReleaseID: publishedID.String, ExpiresAt: expiresAt.UTC(),
	}, nil
}

func (s *SQLite) SitePreviewSession(
	ctx context.Context,
	originLabel string,
	tokenHash [32]byte,
	now time.Time,
) (site.Preview, error) {
	var value site.Site
	var draftID, publishedID sql.NullString
	var createdAt, updatedAt, expiresAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.owner_user_id, owner.username, s.name, s.title, s.enabled,
		       s.created_at, s.updated_at, s.draft_release_id, s.published_release_id,
		       p.expires_at
		FROM site_preview_sessions AS p
		JOIN sites AS s ON s.id = p.site_id
		JOIN users AS owner ON owner.id = s.owner_user_id
		JOIN users AS viewer ON viewer.id = p.user_id
		WHERE p.token_hash = ? AND p.origin_label = ? AND p.expires_at > ?
		  AND s.draft_release_id IS NOT NULL AND viewer.status = ?`,
		tokenHash[:], originLabel, unix(now), auth.UserActive,
	).Scan(
		&value.ID, &value.OwnerUserID, &value.OwnerUsername, &value.Name,
		&value.Title, &value.Enabled, &createdAt, &updatedAt,
		&draftID, &publishedID, &expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return site.Preview{}, site.ErrInvalidPreview
	}
	if err != nil {
		return site.Preview{}, fmt.Errorf("query site preview session: %w", err)
	}
	value.CreatedAt = time.Unix(createdAt, 0).UTC()
	value.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	value.DraftReleaseID = draftID.String
	value.PublishedReleaseID = publishedID.String
	return site.Preview{
		Site: value, DraftReleaseID: draftID.String,
		PublishedReleaseID: publishedID.String,
		ExpiresAt:          time.Unix(expiresAt, 0).UTC(),
	}, nil
}

func recordCrossOwnerSiteAudit(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID, ownerUserID, siteID, name, kind string,
	includeAll bool,
	now time.Time,
) error {
	if actorUserID == ownerUserID {
		return nil
	}
	if !includeAll {
		return site.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO site_audit_events (
			occurred_at, actor_user_id, owner_user_id, site_id, name, kind
		) VALUES (?, ?, ?, ?, ?, ?)`,
		unix(now), actorUserID, ownerUserID, siteID, name, kind,
	); err != nil {
		return fmt.Errorf("record cross-owner site audit: %w", err)
	}
	return nil
}

func scanSite(row rowScanner) (site.Site, error) {
	var value site.Site
	var createdAt, updatedAt int64
	var draftID, publishedID sql.NullString
	if err := row.Scan(
		&value.ID, &value.OwnerUserID, &value.OwnerUsername,
		&value.Name, &value.Title, &value.Enabled,
		&createdAt, &updatedAt, &draftID, &publishedID,
	); err != nil {
		return site.Site{}, err
	}
	value.CreatedAt = time.Unix(createdAt, 0).UTC()
	value.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	value.DraftReleaseID = draftID.String
	value.PublishedReleaseID = publishedID.String
	return value, nil
}

func scanRelease(row rowScanner) (site.Release, error) {
	var value site.Release
	var digest []byte
	var createdAt int64
	var publishedAt sql.NullInt64
	if err := row.Scan(
		&value.ID, &value.SiteID, &value.Version, &value.FileCount,
		&value.TotalBytes, &digest, &createdAt, &publishedAt,
	); err != nil {
		return site.Release{}, fmt.Errorf("scan site release: %w", err)
	}
	if len(digest) != len(value.Digest) {
		return site.Release{}, errors.New("stored site release digest has invalid length")
	}
	copy(value.Digest[:], digest)
	value.CreatedAt = time.Unix(createdAt, 0).UTC()
	if publishedAt.Valid {
		value.PublishedAt = time.Unix(publishedAt.Int64, 0).UTC()
	}
	return value, nil
}
