package updater

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/internal/buildinfo"
)

type fakeUpdateRepository struct {
	mu       sync.Mutex
	settings Settings
	events   []Event
}

func (r *fakeUpdateRepository) UpdateSettings(context.Context) (Settings, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.settings, nil
}

func (r *fakeUpdateRepository) SaveUpdateSettings(_ context.Context, settings Settings, event Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings = settings
	r.events = append(r.events, event)
	return nil
}

func (r *fakeUpdateRepository) RecordUpdateEvent(_ context.Context, event Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

type fakeReleaseClient struct {
	release Release
	staged  string
	checks  chan struct{}
}

func (c *fakeReleaseClient) Check(context.Context) (Release, bool, error) {
	select {
	case c.checks <- struct{}{}:
	default:
	}
	return c.release, true, nil
}

func (c *fakeReleaseClient) Stage(context.Context, Release, string) (string, error) {
	return c.staged, nil
}

func TestManagerCheckSkipAndApply(t *testing.T) {
	t.Parallel()
	repository := &fakeUpdateRepository{settings: Settings{Mode: ModeNotify}}
	client := &fakeReleaseClient{
		release: Release{Version: "v1.1.0", PublishedAt: time.Now().UTC()},
		staged:  "/tmp/staged-wispdeck", checks: make(chan struct{}, 4),
	}
	requests := make(chan ApplyRequest, 1)
	manager, err := NewManager(context.Background(), ManagerConfig{
		Client: client, Repository: repository, Current: buildinfo.Info{Version: "v1.0.0"},
		StagingDir: "/tmp/updates", InitialDelay: time.Hour, CheckInterval: time.Hour,
		RequestApply: func(request ApplyRequest) error { requests <- request; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.Start(context.Background())
	t.Cleanup(manager.Close)
	actor := Actor{UserID: "user-1", Username: "alice", ClientIP: "192.0.2.1"}
	if !manager.QueueCheck(actor) {
		t.Fatal("failed to queue update check")
	}
	select {
	case <-client.checks:
	case <-time.After(time.Second):
		t.Fatal("update check did not run")
	}
	eventually(t, func() bool { return manager.Snapshot().Available })
	if err := manager.SkipLatest(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	if manager.Snapshot().Available {
		t.Fatal("skipped release remained available")
	}
	if err := manager.SetMode(context.Background(), actor, ModeNotify); err != nil {
		t.Fatal(err)
	}
	if err := manager.ClearSkipped(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	if !manager.QueueApply(actor) {
		t.Fatal("failed to queue update apply")
	}
	select {
	case request := <-requests:
		if request.Release.Version != "v1.1.0" || request.StagedPath != client.staged {
			t.Fatalf("apply request = %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("update apply was not requested")
	}
}

func TestManagerTreatsTypedNilClientAsUnconfigured(t *testing.T) {
	t.Parallel()
	repository := &fakeUpdateRepository{settings: Settings{Mode: ModeNotify}}
	var client *Client
	manager, err := NewManager(context.Background(), ManagerConfig{
		Client: client, Repository: repository, Current: buildinfo.Info{Version: "dev"},
		StagingDir: "/tmp/updates", RequestApply: func(ApplyRequest) error { return nil },
		InitialDelay: time.Hour, CheckInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if manager.Snapshot().Configured {
		t.Fatal("typed nil update client was treated as configured")
	}
	manager.check(context.Background(), Actor{})
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not satisfied")
}
