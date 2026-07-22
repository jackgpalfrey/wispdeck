package updater

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/wispdeck/wispdeck/internal/buildinfo"
	"github.com/wispdeck/wispdeck/internal/updatepolicy"
)

type Mode = updatepolicy.Mode
type Settings = updatepolicy.Settings
type Actor = updatepolicy.Actor
type Event = updatepolicy.Event

const (
	ModeNotify           = updatepolicy.ModeNotify
	ModeAutomatic        = updatepolicy.ModeAutomatic
	ModeDisabled         = updatepolicy.ModeDisabled
	DefaultCheckInterval = 6 * time.Hour
)

func ValidMode(mode Mode) bool {
	return updatepolicy.ValidMode(mode)
}

type Repository interface {
	UpdateSettings(context.Context) (Settings, error)
	SaveUpdateSettings(context.Context, Settings, Event) error
	RecordUpdateEvent(context.Context, Event) error
}

type ApplyRequest struct {
	Release    Release
	StagedPath string
}

type ManagerConfig struct {
	Client        ReleaseClient
	Repository    Repository
	Current       buildinfo.Info
	StagingDir    string
	RequestApply  func(ApplyRequest) error
	Logger        *slog.Logger
	CheckInterval time.Duration
	InitialDelay  time.Duration
	Now           func() time.Time
}

type ReleaseClient interface {
	Check(context.Context) (Release, bool, error)
	Stage(context.Context, Release, string) (string, error)
}

type Snapshot struct {
	Configured     bool
	Current        buildinfo.Info
	Mode           Mode
	SkippedVersion string
	Latest         Release
	Available      bool
	Checking       bool
	Applying       bool
	LastCheckedAt  time.Time
	LastError      string
}

type actionKind uint8

const (
	actionCheck actionKind = iota + 1
	actionApply
)

type action struct {
	kind  actionKind
	actor Actor
}

type Manager struct {
	config ManagerConfig

	policyMu sync.Mutex
	mu       sync.RWMutex
	settings Settings
	latest   Release
	checking bool
	applying bool
	checked  time.Time
	lastErr  string

	actions chan action
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewManager(ctx context.Context, config ManagerConfig) (*Manager, error) {
	if config.Repository == nil {
		return nil, errors.New("update repository is required")
	}
	if nilReleaseClient(config.Client) {
		config.Client = nil
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = DefaultCheckInterval
	}
	if config.InitialDelay < 0 {
		return nil, errors.New("update initial delay cannot be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	settings, err := config.Repository.UpdateSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("load update settings: %w", err)
	}
	if !ValidMode(settings.Mode) {
		return nil, fmt.Errorf("stored update mode %q is invalid", settings.Mode)
	}
	return &Manager{
		config: config, settings: settings,
		actions: make(chan action, 8), done: make(chan struct{}),
	}, nil
}

func nilReleaseClient(client ReleaseClient) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (m *Manager) Start(parent context.Context) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.mu.Unlock()
	go m.loop(ctx)
}

func (m *Manager) Close() {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-m.done
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	configured := m.config.Client != nil && m.config.RequestApply != nil && m.config.StagingDir != ""
	available := configured && m.latest.Version != "" && m.latest.Version != m.settings.SkippedVersion &&
		m.settings.Mode != ModeDisabled
	return Snapshot{
		Configured: configured, Current: m.config.Current, Mode: m.settings.Mode,
		SkippedVersion: m.settings.SkippedVersion, Latest: m.latest,
		Available: available, Checking: m.checking, Applying: m.applying,
		LastCheckedAt: m.checked, LastError: m.lastErr,
	}
}

func (m *Manager) QueueCheck(actor Actor) bool {
	return m.queue(action{kind: actionCheck, actor: actor})
}

func (m *Manager) QueueApply(actor Actor) bool {
	return m.queue(action{kind: actionApply, actor: actor})
}

func (m *Manager) queue(value action) bool {
	select {
	case m.actions <- value:
		return true
	default:
		return false
	}
}

func (m *Manager) SetMode(ctx context.Context, actor Actor, mode Mode) error {
	if !ValidMode(mode) {
		return errors.New("invalid update mode")
	}
	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	m.mu.RLock()
	settings := m.settings
	m.mu.RUnlock()
	settings.Mode = mode
	settings.UpdatedAt = m.config.Now().UTC()
	event := Event{
		OccurredAt: settings.UpdatedAt, Actor: actor, Kind: "settings_changed",
		Details: "mode=" + string(mode),
	}
	if err := m.config.Repository.SaveUpdateSettings(ctx, settings, event); err != nil {
		return err
	}
	m.mu.Lock()
	m.settings = settings
	m.mu.Unlock()
	if mode != ModeDisabled {
		m.QueueCheck(actor)
	}
	return nil
}

func (m *Manager) SkipLatest(ctx context.Context, actor Actor) error {
	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	m.mu.RLock()
	settings := m.settings
	latest := m.latest
	m.mu.RUnlock()
	if latest.Version == "" {
		return errors.New("there is no available update to skip")
	}
	settings.SkippedVersion = latest.Version
	settings.UpdatedAt = m.config.Now().UTC()
	event := Event{
		OccurredAt: settings.UpdatedAt, Actor: actor, Kind: "version_skipped",
		Version: latest.Version,
	}
	if err := m.config.Repository.SaveUpdateSettings(ctx, settings, event); err != nil {
		return err
	}
	m.mu.Lock()
	m.settings = settings
	m.mu.Unlock()
	return nil
}

func (m *Manager) ClearSkipped(ctx context.Context, actor Actor) error {
	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	m.mu.RLock()
	settings := m.settings
	m.mu.RUnlock()
	if settings.SkippedVersion == "" {
		return nil
	}
	settings.SkippedVersion = ""
	settings.UpdatedAt = m.config.Now().UTC()
	event := Event{
		OccurredAt: settings.UpdatedAt, Actor: actor, Kind: "settings_changed",
		Details: "cleared skipped version",
	}
	if err := m.config.Repository.SaveUpdateSettings(ctx, settings, event); err != nil {
		return err
	}
	m.mu.Lock()
	m.settings = settings
	m.mu.Unlock()
	return nil
}

func (m *Manager) loop(ctx context.Context) {
	defer close(m.done)
	timer := time.NewTimer(m.config.InitialDelay)
	defer timer.Stop()
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.check(ctx, Actor{})
		case <-ticker.C:
			m.check(ctx, Actor{})
		case queued := <-m.actions:
			switch queued.kind {
			case actionCheck:
				m.check(ctx, queued.actor)
			case actionApply:
				m.apply(ctx, queued.actor)
			}
		}
	}
}

func (m *Manager) check(ctx context.Context, actor Actor) {
	snapshot := m.Snapshot()
	if !snapshot.Configured || snapshot.Mode == ModeDisabled || snapshot.Checking || snapshot.Applying {
		return
	}
	m.setWork(true, false, "")
	release, available, err := m.config.Client.Check(ctx)
	now := m.config.Now().UTC()
	m.mu.Lock()
	m.checking = false
	m.checked = now
	if err != nil {
		m.lastErr = safeError(err)
	} else {
		m.lastErr = ""
		if available {
			m.latest = release
		} else {
			m.latest = Release{}
		}
	}
	settings := m.settings
	m.mu.Unlock()
	if err != nil {
		m.config.Logger.Warn("update check failed", "error", err)
		return
	}
	if actor.UserID != "" {
		_ = m.config.Repository.RecordUpdateEvent(ctx, Event{
			OccurredAt: now, Actor: actor, Kind: "check_requested", Version: release.Version,
		})
	}
	if available && settings.Mode == ModeAutomatic && settings.SkippedVersion != release.Version {
		m.apply(ctx, Actor{})
	}
}

func (m *Manager) apply(ctx context.Context, actor Actor) {
	snapshot := m.Snapshot()
	if !snapshot.Configured || !snapshot.Available || snapshot.Applying || snapshot.Checking {
		return
	}
	m.setWork(false, true, "")
	path, err := m.config.Client.Stage(ctx, snapshot.Latest, m.config.StagingDir)
	if err == nil {
		err = m.config.RequestApply(ApplyRequest{Release: snapshot.Latest, StagedPath: path})
	}
	if err != nil {
		m.mu.Lock()
		m.applying = false
		m.lastErr = safeError(err)
		m.mu.Unlock()
		m.config.Logger.Error("stage update", "version", snapshot.Latest.Version, "error", err)
		return
	}
	_ = m.config.Repository.RecordUpdateEvent(ctx, Event{
		OccurredAt: m.config.Now().UTC(), Actor: actor, Kind: "update_requested",
		Version: snapshot.Latest.Version,
	})
}

func (m *Manager) setWork(checking, applying bool, lastError string) {
	m.mu.Lock()
	m.checking = checking
	m.applying = applying
	m.lastErr = lastError
	m.mu.Unlock()
}

func safeError(err error) string {
	value := strings.TrimSpace(err.Error())
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}
