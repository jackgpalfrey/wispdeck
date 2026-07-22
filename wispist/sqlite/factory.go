// Package sqlite implements Wispist's per-store SQLite persistence backend.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wispdeck/wispdeck/wispist"
	_ "modernc.org/sqlite"
)

type Factory struct {
	directory string

	mu      sync.Mutex
	entries map[string]*cacheEntry
	closed  bool
	now     func() time.Time
	maxOpen int
	idleFor time.Duration
	evicted uint64
}

type cacheEntry struct {
	ready chan struct{}
	store *Store
	err   error
	refs  int
	used  time.Time
}

type storeLease struct {
	*Store
	factory *Factory
	entry   *cacheEntry
	once    sync.Once
}

func NewFactory(directory string) (*Factory, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("wispist data directory is required")
	}
	return &Factory{
		directory: filepath.Clean(directory), entries: make(map[string]*cacheEntry),
		now: time.Now, maxOpen: 32, idleFor: 5 * time.Minute,
	}, nil
}

func (f *Factory) Open(ctx context.Context, key string, create bool) (wispist.Store, error) {
	if !validStoreKey(key) {
		return nil, errors.New("invalid wispist store key")
	}
	now := f.now().UTC()
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, errors.New("wispist store factory is closed")
	}
	f.pruneLocked(now)
	if entry := f.entries[key]; entry != nil {
		entry.refs++
		entry.used = now
		f.mu.Unlock()
		store, err := f.waitForEntry(ctx, entry)
		if create && errors.Is(err, wispist.ErrStoreNotFound) {
			return f.Open(ctx, key, true)
		}
		return store, err
	}
	if len(f.entries) >= f.maxOpen {
		f.evictOneLocked()
	}
	if len(f.entries) >= f.maxOpen {
		f.mu.Unlock()
		return nil, wispist.ErrStoreUnavailable
	}
	entry := &cacheEntry{ready: make(chan struct{}), refs: 1, used: now}
	f.entries[key] = entry
	f.mu.Unlock()

	store, err := f.openStore(ctx, key, create)
	f.mu.Lock()
	entry.store = store
	entry.err = err
	if err != nil {
		delete(f.entries, key)
	}
	close(entry.ready)
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &storeLease{Store: store, factory: f, entry: entry}, nil
}

func (f *Factory) waitForEntry(ctx context.Context, entry *cacheEntry) (wispist.Store, error) {
	select {
	case <-entry.ready:
		if entry.err != nil {
			f.release(entry)
			return nil, entry.err
		}
		return &storeLease{Store: entry.store, factory: f, entry: entry}, nil
	case <-ctx.Done():
		f.release(entry)
		return nil, ctx.Err()
	}
}

func (lease *storeLease) Close() error {
	lease.once.Do(func() { lease.factory.release(lease.entry) })
	return nil
}

func (f *Factory) release(entry *cacheEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if entry.refs > 0 {
		entry.refs--
	}
	entry.used = f.now().UTC()
	if f.closed && entry.refs == 0 && entry.store != nil {
		_ = entry.store.Close()
		for key, candidate := range f.entries {
			if candidate == entry {
				delete(f.entries, key)
				break
			}
		}
	}
}

func (f *Factory) pruneLocked(now time.Time) {
	for key, entry := range f.entries {
		if entry.store != nil && entry.refs == 0 && now.Sub(entry.used) >= f.idleFor {
			_ = entry.store.Close()
			delete(f.entries, key)
			f.evicted++
		}
	}
}

func (f *Factory) evictOneLocked() {
	var oldestKey string
	var oldest *cacheEntry
	for key, entry := range f.entries {
		if entry.store == nil || entry.refs != 0 || oldest != nil && !entry.used.Before(oldest.used) {
			continue
		}
		oldestKey, oldest = key, entry
	}
	if oldest != nil {
		_ = oldest.store.Close()
		delete(f.entries, oldestKey)
		f.evicted++
	}
}

type FactoryStats struct {
	OpenStores int
	InUse      int
	Evictions  uint64
}

// Stats returns a bounded snapshot suitable for host-owned metrics.
func (f *Factory) Stats() FactoryStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := FactoryStats{OpenStores: len(f.entries), Evictions: f.evicted}
	for _, entry := range f.entries {
		if entry.refs > 0 {
			stats.InUse++
		}
	}
	return stats
}

// Close prevents new opens and closes every currently idle store. Stores in
// use are closed when their final lease is released.
func (f *Factory) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	var result error
	for key, entry := range f.entries {
		if entry.store != nil && entry.refs == 0 {
			result = errors.Join(result, entry.store.Close())
			delete(f.entries, key)
		}
	}
	return result
}

func (f *Factory) openStore(ctx context.Context, key string, create bool) (*Store, error) {
	if create {
		if err := os.MkdirAll(f.directory, 0o700); err != nil {
			return nil, fmt.Errorf("create wispist data directory: %w", err)
		}
		directory, err := os.Lstat(f.directory)
		if err != nil || !directory.IsDir() {
			return nil, errors.New("wispist data path is not a directory")
		}
		if err := os.Chmod(f.directory, 0o700); err != nil {
			return nil, fmt.Errorf("restrict wispist data directory permissions: %w", err)
		}
	}
	path := filepath.Join(f.directory, key+".db")
	info, inspectErr := os.Lstat(path)
	if errors.Is(inspectErr, os.ErrNotExist) {
		if !create {
			return nil, wispist.ErrStoreNotFound
		}
	} else if inspectErr != nil {
		return nil, fmt.Errorf("inspect wispist store: %w", inspectErr)
	} else if !info.Mode().IsRegular() {
		return nil, errors.New("wispist store path is not a regular file")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open wispist store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	cleanup := func(err error) (*Store, error) {
		_ = db.Close()
		return nil, err
	}
	for _, statement := range []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA secure_delete = ON`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return cleanup(fmt.Errorf("configure wispist store: %w", err))
		}
	}
	if err := migrate(ctx, db); err != nil {
		return cleanup(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return cleanup(fmt.Errorf("restrict wispist store permissions: %w", err))
	}
	return &Store{db: db}, nil
}

func validStoreKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range []byte(value) {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}
