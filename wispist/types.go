// Package wispist provides an embeddable backend engine for static websites.
package wispist

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

const (
	ProtocolVersion = 1
	ProblemBaseURL  = "https://learn.peios.org/wispist/problems/"
)

type Mode string

const (
	ModeLive        Mode = "live"
	ModeDraft       Mode = "draft"
	ModeLivePreview Mode = "live-preview"
)

type PrincipalKind string

const (
	PrincipalAnonymous     PrincipalKind = "anonymous"
	PrincipalAuthenticated PrincipalKind = "authenticated"
	PrincipalCapability    PrincipalKind = "capability"
	PrincipalService       PrincipalKind = "service"
)

type Principal struct {
	Kind    PrincipalKind
	Subject string
	Claims  map[string]string
}

// Binding is the complete host-provided context for one Wispist request. Its
// namespace and store key are opaque to the engine.
type Binding struct {
	StoreKey          string
	Namespace         string
	Origin            string
	ClientKey         string
	Principal         Principal
	Declaration       Declaration
	Mode              Mode
	ReadOnly          bool
	MaxNamespaceBytes int64
}

type Operation string

const (
	OperationList      Operation = "list"
	OperationRead      Operation = "read"
	OperationCreate    Operation = "create"
	OperationUpdate    Operation = "update"
	OperationDelete    Operation = "delete"
	OperationSubscribe Operation = "subscribe"
)

func (o Operation) mutation() bool {
	return o == OperationCreate || o == OperationUpdate || o == OperationDelete
}

type Access string

const (
	AccessAnyone        Access = "anyone"
	AccessAuthenticated Access = "authenticated"
	AccessNobody        Access = "nobody"
)

type CollectionPolicy struct {
	Access           map[Operation]Access
	MaxDocuments     int
	MaxDocumentBytes int
}

type Declaration struct {
	Version     int
	Collections map[string]CollectionPolicy
}

func EmptyDeclaration() Declaration {
	return Declaration{Version: ProtocolVersion, Collections: map[string]CollectionPolicy{}}
}

type Limits struct {
	MaxCollections           int
	MaxDocuments             int
	MaxDocumentBytes         int
	MaxNamespaceBytes        int64
	MaxDraftNamespaceBytes   int64
	DefaultListLimit         int
	MaxListLimit             int
	MaxSubscribedCollections int
	MaxRequestEnvelopeBytes  int64
	MaxIdempotencyRecords    int
	ChangeRetentionEntries   int
	ChangeRetentionAge       time.Duration
	IdempotencyRetention     time.Duration
	SSEQueueSize             int
	SSEHeartbeat             time.Duration
}

// RateLimits bounds work performed by one Engine. ClientKey and StoreKey are
// opaque host-provided dimensions; Wispist never attempts to interpret proxy
// headers itself.
type RateLimits struct {
	ReadsPerMinute             int
	ReadBurst                  int
	MutationsPerMinute         int
	MutationBurst              int
	SiteMutationsPerMinute     int
	SiteMutationBurst          int
	GeneratedDocumentsPerDay   int
	GeneratedDocumentBurst     int
	InstallationRequestsMinute int
	InstallationRequestBurst   int
	SSEPerClientSite           int
	SSEPerSite                 int
	MaxBuckets                 int
	BucketIdleTime             time.Duration
}

type ObservationEvent string

const (
	ObservationRequest     ObservationEvent = "request"
	ObservationStream      ObservationEvent = "stream"
	ObservationStreamReset ObservationEvent = "stream_reset"
)

// Observation contains only bounded, non-sensitive dimensions. An Observer
// must return promptly; Engine invokes it synchronously and recovers its panic.
type Observation struct {
	Event       ObservationEvent
	Operation   string
	Mode        Mode
	Status      int
	ProblemType string
	Duration    time.Duration
	Delta       int
	Reason      string
}

type Observer interface {
	Observe(context.Context, Observation)
}

type ObserverFunc func(context.Context, Observation)

func (function ObserverFunc) Observe(ctx context.Context, observation Observation) {
	function(ctx, observation)
}

func DefaultRateLimits() RateLimits {
	return RateLimits{
		ReadsPerMinute:             600,
		ReadBurst:                  100,
		MutationsPerMinute:         60,
		MutationBurst:              20,
		SiteMutationsPerMinute:     300,
		SiteMutationBurst:          60,
		GeneratedDocumentsPerDay:   10_000,
		GeneratedDocumentBurst:     100,
		InstallationRequestsMinute: 6_000,
		InstallationRequestBurst:   1_000,
		SSEPerClientSite:           6,
		SSEPerSite:                 100,
		MaxBuckets:                 10_000,
		BucketIdleTime:             30 * time.Minute,
	}
}

func DefaultLimits() Limits {
	return Limits{
		MaxCollections:           32,
		MaxDocuments:             1_000,
		MaxDocumentBytes:         32 << 10,
		MaxNamespaceBytes:        10 << 20,
		MaxDraftNamespaceBytes:   5 << 20,
		DefaultListLimit:         100,
		MaxListLimit:             250,
		MaxSubscribedCollections: 8,
		MaxRequestEnvelopeBytes:  4 << 10,
		MaxIdempotencyRecords:    10_000,
		ChangeRetentionEntries:   10_000,
		ChangeRetentionAge:       7 * 24 * time.Hour,
		IdempotencyRetention:     24 * time.Hour,
		SSEQueueSize:             128,
		SSEHeartbeat:             25 * time.Second,
	}
}

type Document struct {
	ID        string          `json:"id"`
	Revision  string          `json:"revision"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
	Data      json.RawMessage `json:"data"`
}

type ListPage struct {
	Documents    []Document
	After        string
	ChangeCursor string
}

type ChangeOperation string

const (
	ChangeCreate ChangeOperation = "create"
	ChangeUpdate ChangeOperation = "update"
	ChangeDelete ChangeOperation = "delete"
)

type Change struct {
	Sequence   uint64
	Cursor     string
	Collection string
	Operation  ChangeOperation
	Document   *Document
	ID         string
	Revision   string
}

type ChangesPage struct {
	Changes []Change
	Cursor  string
	More    bool
}

// CollectionUsage is a logical storage summary for one collection. Bytes
// counts normalized document JSON only; database indexes, retained changes,
// and SQLite bookkeeping are intentionally excluded.
type CollectionUsage struct {
	Name      string `json:"name"`
	Documents int    `json:"documents"`
	Bytes     int64  `json:"bytes"`
}

// NamespaceUsage is the bounded logical usage exposed to a host's management
// plane. Collections contains only collections with stored documents; a host
// can merge in empty collections from its own declaration or schema.
type NamespaceUsage struct {
	Namespace   string            `json:"namespace"`
	Documents   int               `json:"documents"`
	Bytes       int64             `json:"bytes"`
	Collections []CollectionUsage `json:"collections"`
}

// NamespaceSnapshot is a consistent export of one namespace. Documents are
// ordered by collection and then creation order.
type NamespaceSnapshot struct {
	Namespace   string                `json:"namespace"`
	Collections map[string][]Document `json:"collections"`
}

type MutationLimits struct {
	MaxDocuments           int
	MaxDocumentBytes       int
	MaxNamespaceBytes      int64
	MaxIdempotencyRecords  int
	ChangeRetentionEntries int
	ChangeRetentionAge     time.Duration
	IdempotencyRetention   time.Duration
}

type CreateRequest struct {
	Namespace      string
	Collection     string
	ID             string
	Data           json.RawMessage
	IdempotencyKey string
	Fingerprint    [32]byte
	Now            time.Time
	Limits         MutationLimits
}

type PutRequest struct {
	Namespace        string
	Collection       string
	ID               string
	Data             json.RawMessage
	CreateOnly       bool
	ExpectedRevision string
	Now              time.Time
	Limits           MutationLimits
}

type DeleteRequest struct {
	Namespace        string
	Collection       string
	ID               string
	ExpectedRevision string
	Now              time.Time
	Limits           MutationLimits
}

type ClearCollectionRequest struct {
	Namespace  string
	Collection string
	Now        time.Time
	Limits     MutationLimits
}

var (
	ErrStoreNotFound       = errors.New("wispist store not found")
	ErrDocumentNotFound    = errors.New("wispist document not found")
	ErrInvalidDocumentData = errors.New("wispist document data must be a valid JSON object")
	ErrRevisionConflict    = errors.New("wispist revision conflict")
	ErrQuotaExceeded       = errors.New("wispist quota exceeded")
	ErrIdempotencyConflict = errors.New("wispist idempotency conflict")
	ErrStoreUnavailable    = errors.New("wispist store temporarily unavailable")
	ErrInvalidCursor       = errors.New("wispist cursor is invalid")
	ErrCursorExpired       = errors.New("wispist cursor has expired")
)

type Store interface {
	Close() error
	List(context.Context, string, string, int, string) (ListPage, error)
	Get(context.Context, string, string, string) (Document, error)
	Usage(context.Context, string) (NamespaceUsage, error)
	Snapshot(context.Context, string) (NamespaceSnapshot, error)
	SnapshotNamespaces(context.Context, []string) (map[string]NamespaceSnapshot, error)
	Create(context.Context, CreateRequest) (Document, Change, bool, error)
	Put(context.Context, PutRequest) (Document, Change, error)
	Delete(context.Context, DeleteRequest) (Change, error)
	ClearCollection(context.Context, ClearCollectionRequest) ([]Change, error)
	PurgeNamespace(context.Context, string) error
	HighWater(context.Context, string) (string, error)
	Changes(context.Context, string, []string, string, int) (ChangesPage, error)
}

type StoreFactory interface {
	Open(context.Context, string, bool) (Store, error)
}

type AuthorizationRequest struct {
	Binding    Binding
	Operation  Operation
	Collection string
	DocumentID string
	Current    *Document
	Proposed   json.RawMessage
}

type AuthorizationDecision struct {
	Allowed                bool
	AuthenticationRequired bool
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) AuthorizationDecision
}

type DeclarativeAuthorizer struct{}

func (DeclarativeAuthorizer) Authorize(_ context.Context, request AuthorizationRequest) AuthorizationDecision {
	if request.Binding.ReadOnly && request.Operation.mutation() {
		return AuthorizationDecision{}
	}
	collection, ok := request.Binding.Declaration.Collections[request.Collection]
	if !ok {
		return AuthorizationDecision{}
	}
	access, ok := collection.Access[request.Operation]
	if !ok || access == AccessNobody {
		return AuthorizationDecision{}
	}
	if access == AccessAnyone {
		return AuthorizationDecision{Allowed: true}
	}
	authenticated := request.Binding.Principal.Kind == PrincipalAuthenticated ||
		request.Binding.Principal.Kind == PrincipalService
	return AuthorizationDecision{Allowed: authenticated, AuthenticationRequired: !authenticated}
}

type Config struct {
	StoreFactory StoreFactory
	Authorizer   Authorizer
	Limits       Limits
	RateLimits   RateLimits
	Logger       *slog.Logger
	Observer     Observer
	Now          func() time.Time
}
