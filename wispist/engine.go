package wispist

import (
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

//go:embed client/v1.js
var clientFiles embed.FS

type Engine struct {
	stores       StoreFactory
	authorizer   Authorizer
	limits       Limits
	rateLimits   RateLimits
	limiter      *requestLimiter
	logger       *slog.Logger
	now          func() time.Time
	hub          *changeHub
	client       []byte
	clientDigest [32]byte
	observer     Observer
}

func NewEngine(config Config) (*Engine, error) {
	if config.StoreFactory == nil {
		return nil, errors.New("wispist store factory is required")
	}
	limits, err := normalizeLimits(config.Limits)
	if err != nil {
		return nil, err
	}
	rateLimits, err := normalizeRateLimits(config.RateLimits)
	if err != nil {
		return nil, err
	}
	if config.Authorizer == nil {
		config.Authorizer = DeclarativeAuthorizer{}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	client, err := clientFiles.ReadFile("client/v1.js")
	if err != nil {
		return nil, fmt.Errorf("read embedded Wispist client: %w", err)
	}
	return &Engine{
		stores: config.StoreFactory, authorizer: config.Authorizer, limits: limits,
		rateLimits: rateLimits, limiter: newRequestLimiter(rateLimits),
		logger: config.Logger, observer: config.Observer, now: config.Now, hub: newChangeHub(limits.SSEQueueSize),
		client: client, clientDigest: sha256.Sum256(client),
	}, nil
}

func (e *Engine) Limits() Limits { return e.limits }

func (e *Engine) RateLimits() RateLimits { return e.rateLimits }

func (e *Engine) ParseDeclaration(data []byte) (Declaration, error) {
	return ParseDeclaration(data, e.limits)
}

func normalizeLimits(value Limits) (Limits, error) {
	defaults := DefaultLimits()
	if value == (Limits{}) {
		return defaults, nil
	}
	if value.MaxCollections == 0 {
		value.MaxCollections = defaults.MaxCollections
	}
	if value.MaxDocuments == 0 {
		value.MaxDocuments = defaults.MaxDocuments
	}
	if value.MaxDocumentBytes == 0 {
		value.MaxDocumentBytes = defaults.MaxDocumentBytes
	}
	if value.MaxNamespaceBytes == 0 {
		value.MaxNamespaceBytes = defaults.MaxNamespaceBytes
	}
	if value.MaxDraftNamespaceBytes == 0 {
		value.MaxDraftNamespaceBytes = defaults.MaxDraftNamespaceBytes
	}
	if value.DefaultListLimit == 0 {
		value.DefaultListLimit = defaults.DefaultListLimit
	}
	if value.MaxListLimit == 0 {
		value.MaxListLimit = defaults.MaxListLimit
	}
	if value.MaxSubscribedCollections == 0 {
		value.MaxSubscribedCollections = defaults.MaxSubscribedCollections
	}
	if value.MaxRequestEnvelopeBytes == 0 {
		value.MaxRequestEnvelopeBytes = defaults.MaxRequestEnvelopeBytes
	}
	if value.MaxIdempotencyRecords == 0 {
		value.MaxIdempotencyRecords = defaults.MaxIdempotencyRecords
	}
	if value.ChangeRetentionEntries == 0 {
		value.ChangeRetentionEntries = defaults.ChangeRetentionEntries
	}
	if value.ChangeRetentionAge == 0 {
		value.ChangeRetentionAge = defaults.ChangeRetentionAge
	}
	if value.IdempotencyRetention == 0 {
		value.IdempotencyRetention = defaults.IdempotencyRetention
	}
	if value.SSEQueueSize == 0 {
		value.SSEQueueSize = defaults.SSEQueueSize
	}
	if value.SSEHeartbeat == 0 {
		value.SSEHeartbeat = defaults.SSEHeartbeat
	}
	if value.MaxCollections < 1 || value.MaxCollections > 256 ||
		value.MaxDocuments < 1 || value.MaxDocumentBytes < 2 ||
		value.MaxNamespaceBytes < int64(value.MaxDocumentBytes) ||
		value.MaxDraftNamespaceBytes < int64(value.MaxDocumentBytes) ||
		value.DefaultListLimit < 1 || value.MaxListLimit < value.DefaultListLimit ||
		value.MaxSubscribedCollections < 1 || value.MaxRequestEnvelopeBytes < 1 ||
		value.MaxIdempotencyRecords < 1 || value.ChangeRetentionEntries < 1 ||
		value.ChangeRetentionAge <= 0 || value.IdempotencyRetention <= 0 ||
		value.SSEQueueSize < 1 || value.SSEHeartbeat <= 0 {
		return Limits{}, errors.New("wispist limits are invalid")
	}
	return value, nil
}

func normalizeRateLimits(value RateLimits) (RateLimits, error) {
	defaults := DefaultRateLimits()
	if value == (RateLimits{}) {
		return defaults, nil
	}
	if value.ReadsPerMinute == 0 {
		value.ReadsPerMinute = defaults.ReadsPerMinute
	}
	if value.ReadBurst == 0 {
		value.ReadBurst = defaults.ReadBurst
	}
	if value.MutationsPerMinute == 0 {
		value.MutationsPerMinute = defaults.MutationsPerMinute
	}
	if value.MutationBurst == 0 {
		value.MutationBurst = defaults.MutationBurst
	}
	if value.SiteMutationsPerMinute == 0 {
		value.SiteMutationsPerMinute = defaults.SiteMutationsPerMinute
	}
	if value.SiteMutationBurst == 0 {
		value.SiteMutationBurst = defaults.SiteMutationBurst
	}
	if value.GeneratedDocumentsPerDay == 0 {
		value.GeneratedDocumentsPerDay = defaults.GeneratedDocumentsPerDay
	}
	if value.GeneratedDocumentBurst == 0 {
		value.GeneratedDocumentBurst = defaults.GeneratedDocumentBurst
	}
	if value.InstallationRequestsMinute == 0 {
		value.InstallationRequestsMinute = defaults.InstallationRequestsMinute
	}
	if value.InstallationRequestBurst == 0 {
		value.InstallationRequestBurst = defaults.InstallationRequestBurst
	}
	if value.SSEPerClientSite == 0 {
		value.SSEPerClientSite = defaults.SSEPerClientSite
	}
	if value.SSEPerSite == 0 {
		value.SSEPerSite = defaults.SSEPerSite
	}
	if value.MaxBuckets == 0 {
		value.MaxBuckets = defaults.MaxBuckets
	}
	if value.BucketIdleTime == 0 {
		value.BucketIdleTime = defaults.BucketIdleTime
	}
	if value.ReadsPerMinute < 1 || value.ReadBurst < 1 ||
		value.MutationsPerMinute < 1 || value.MutationBurst < 1 ||
		value.SiteMutationsPerMinute < 1 || value.SiteMutationBurst < 1 ||
		value.GeneratedDocumentsPerDay < 1 || value.GeneratedDocumentBurst < 1 ||
		value.InstallationRequestsMinute < 1 || value.InstallationRequestBurst < 1 ||
		value.SSEPerClientSite < 1 || value.SSEPerSite < value.SSEPerClientSite ||
		value.MaxBuckets < 16 || value.BucketIdleTime <= 0 {
		return RateLimits{}, errors.New("wispist rate limits are invalid")
	}
	return value, nil
}

func (e *Engine) validateBinding(binding Binding) error {
	if strings.TrimSpace(binding.StoreKey) == "" || len(binding.StoreKey) > 128 ||
		strings.TrimSpace(binding.Namespace) == "" || len(binding.Namespace) > 256 ||
		strings.TrimSpace(binding.ClientKey) == "" || len(binding.ClientKey) > 256 {
		return errors.New("wispist binding has an invalid store key, namespace, or client key")
	}
	origin, err := url.Parse(binding.Origin)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") ||
		origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" ||
		(origin.Path != "" && origin.Path != "/") {
		return errors.New("wispist binding has an invalid origin")
	}
	if binding.Mode != ModeLive && binding.Mode != ModeDraft && binding.Mode != ModeLivePreview {
		return errors.New("wispist binding has an invalid mode")
	}
	if err := validateDeclaration(binding.Declaration, e.limits); err != nil {
		return fmt.Errorf("wispist binding has an invalid declaration: %w", err)
	}
	switch binding.Principal.Kind {
	case PrincipalAnonymous:
		if binding.Principal.Subject != "" {
			return errors.New("wispist anonymous principal must not have a subject")
		}
	case PrincipalAuthenticated, PrincipalCapability, PrincipalService:
		if strings.TrimSpace(binding.Principal.Subject) == "" || len(binding.Principal.Subject) > 256 {
			return errors.New("wispist principal has an invalid subject")
		}
	default:
		return errors.New("wispist binding has an invalid principal kind")
	}
	return nil
}

func (e *Engine) namespaceLimit(binding Binding) int64 {
	if binding.MaxNamespaceBytes > 0 && binding.MaxNamespaceBytes < e.limits.MaxNamespaceBytes {
		return binding.MaxNamespaceBytes
	}
	if binding.Mode == ModeDraft {
		return e.limits.MaxDraftNamespaceBytes
	}
	return e.limits.MaxNamespaceBytes
}

func (e *Engine) mutationLimits(binding Binding, policy CollectionPolicy) MutationLimits {
	return MutationLimits{
		MaxDocuments: policy.MaxDocuments, MaxDocumentBytes: policy.MaxDocumentBytes,
		MaxNamespaceBytes:      e.namespaceLimit(binding),
		MaxIdempotencyRecords:  e.limits.MaxIdempotencyRecords,
		ChangeRetentionEntries: e.limits.ChangeRetentionEntries,
		ChangeRetentionAge:     e.limits.ChangeRetentionAge,
		IdempotencyRetention:   e.limits.IdempotencyRetention,
	}
}

func hubNamespace(binding Binding) string { return binding.StoreKey + "\x00" + binding.Namespace }
