package wispist_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wispdeck/wispdeck/wispist"
	wispistsqlite "github.com/wispdeck/wispdeck/wispist/sqlite"
)

type wireDocument struct {
	ID       string          `json:"id"`
	Revision string          `json:"revision"`
	Data     json.RawMessage `json:"data"`
}

type httpFixture struct {
	engine        *wispist.Engine
	binding       wispist.Binding
	dataDirectory string
}

func newHTTPFixture(t *testing.T, rateLimits wispist.RateLimits) httpFixture {
	return newHTTPFixtureWithAuthorizer(t, rateLimits, nil)
}

func newHTTPFixtureWithAuthorizer(t *testing.T, rateLimits wispist.RateLimits, authorizer wispist.Authorizer) httpFixture {
	return newHTTPFixtureWithDependencies(t, rateLimits, authorizer, nil)
}

func newHTTPFixtureWithObserver(t *testing.T, observer wispist.Observer) httpFixture {
	return newHTTPFixtureWithDependencies(t, wispist.DefaultRateLimits(), nil, observer)
}

func newHTTPFixtureWithDependencies(t *testing.T, rateLimits wispist.RateLimits, authorizer wispist.Authorizer, observer wispist.Observer) httpFixture {
	t.Helper()
	dataDirectory := filepath.Join(t.TempDir(), "data")
	factory, err := wispistsqlite.NewFactory(dataDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = factory.Close() })
	engine, err := wispist.NewEngine(wispist.Config{
		StoreFactory: factory, Authorizer: authorizer, Observer: observer, Limits: wispist.DefaultLimits(), RateLimits: rateLimits,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := engine.ParseDeclaration([]byte(`{
		"version":1,
		"collections":{"items":{"access":"shared"}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	return httpFixture{
		engine: engine, dataDirectory: dataDirectory,
		binding: wispist.Binding{
			StoreKey: "site", Namespace: "live", Origin: "https://site.example.test", ClientKey: "198.51.100.1",
			Principal: wispist.Principal{Kind: wispist.PrincipalAnonymous}, Declaration: declaration, Mode: wispist.ModeLive,
		},
	}
}

func TestEngineEmitsBoundedRequestObservation(t *testing.T) {
	t.Parallel()
	var observations []wispist.Observation
	var mutex sync.Mutex
	fixture := newHTTPFixtureWithObserver(t, wispist.ObserverFunc(func(_ context.Context, observation wispist.Observation) {
		mutex.Lock()
		defer mutex.Unlock()
		observations = append(observations, observation)
	}))
	response := fixture.request(http.MethodGet, "/_wispist/v1?unknown=true", "", nil)
	assertProblem(t, response, http.StatusBadRequest, "invalid-request/")
	mutex.Lock()
	defer mutex.Unlock()
	if len(observations) != 1 {
		t.Fatalf("observations = %+v", observations)
	}
	observation := observations[0]
	if observation.Event != wispist.ObservationRequest || observation.Operation != "describe" ||
		observation.Mode != wispist.ModeLive || observation.Status != http.StatusBadRequest ||
		observation.ProblemType != wispist.ProblemBaseURL+"invalid-request/" || observation.Duration < 0 {
		t.Fatalf("observation = %+v", observation)
	}
}

func TestEngineRecoversObserverPanic(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixtureWithObserver(t, wispist.ObserverFunc(func(context.Context, wispist.Observation) {
		panic("host observer failed")
	}))
	response := fixture.request(http.MethodGet, "/_wispist/v1", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("response after observer panic = %d, %s", response.Code, response.Body.String())
	}
}

func (fixture httpFixture) request(method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://site.example.test"+target, strings.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	fixture.engine.ServeHTTP(response, request, fixture.binding)
	return response
}

func decodeDocument(t *testing.T, response *httptest.ResponseRecorder) wireDocument {
	t.Helper()
	var document wireDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, suffix string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body %s", response.Code, status, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
	}
	var problem wispist.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Type != wispist.ProblemBaseURL+suffix || problem.Status != status || problem.Instance != "urn:uuid:"+response.Header().Get("X-Request-ID") {
		t.Fatalf("problem = %+v", problem)
	}
}

func TestEngineHTTPDocumentLifecycleAndProblemDetails(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	response := fixture.request(http.MethodGet, "/_wispist/v1", "", nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("description response = %d, headers %v, body %s", response.Code, response.Header(), response.Body.String())
	}

	headers := map[string]string{
		"Origin": "https://site.example.test", "Sec-Fetch-Site": "same-origin",
		"Content-Type": "application/json", "Idempotency-Key": "1234567890abcdef",
	}
	response = fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents", `{"data":{"text":"Passport","done":false}}`, headers)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") == "" || response.Header().Get("Location") == "" {
		t.Fatalf("create response = %d, headers %v, body %s", response.Code, response.Header(), response.Body.String())
	}
	document := decodeDocument(t, response)
	if document.ID == "" || document.Revision == "" {
		t.Fatalf("created document = %+v", document)
	}
	response = fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents", `{"data":{"text":"Passport","done":false}}`, headers)
	if replayed := decodeDocument(t, response); response.Code != http.StatusCreated || replayed.ID != document.ID || replayed.Revision != document.Revision {
		t.Fatalf("idempotent replay = %d, %+v", response.Code, replayed)
	}

	response = fixture.request(http.MethodGet, "/_wispist/v1/collections/items/documents/"+document.ID, "", nil)
	if got := decodeDocument(t, response); response.Code != http.StatusOK || got.Revision != document.Revision {
		t.Fatalf("read response = %d, %+v", response.Code, got)
	}
	response = fixture.request(http.MethodGet, "/_wispist/v1/collections/items/documents/"+document.ID, "", map[string]string{
		"If-None-Match": `"other", W/"` + document.Revision + `"`,
	})
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("conditional read = %d, %q", response.Code, response.Body.String())
	}
	response = fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/"+document.ID, `{"data":{"done":true}}`, map[string]string{
		"Origin": "https://site.example.test", "Content-Type": "application/json",
	})
	assertProblem(t, response, http.StatusPreconditionRequired, "precondition-required/")
	response = fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/"+document.ID, `{"data":{"done":true}}`, map[string]string{
		"Origin": "https://site.example.test", "Content-Type": "application/json", "If-Match": `"stale-revision-token"`,
	})
	assertProblem(t, response, http.StatusPreconditionFailed, "revision-conflict/")
	response = fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/"+document.ID, `{"data":{"done":true}}`, map[string]string{
		"Origin": "https://site.example.test", "Content-Type": "application/json", "If-Match": `"` + document.Revision + `"`,
	})
	updated := decodeDocument(t, response)
	if response.Code != http.StatusOK || updated.Revision == document.Revision {
		t.Fatalf("replacement response = %d, %+v", response.Code, updated)
	}

	response = fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents", `{"data":{"done":false}}`, map[string]string{
		"Origin": "https://attacker.example", "Content-Type": "application/json", "Idempotency-Key": "abcdef1234567890",
	})
	assertProblem(t, response, http.StatusForbidden, "forbidden/")
	duplicateOrigin := httptest.NewRequest(http.MethodPost, "https://site.example.test/_wispist/v1/collections/items/documents", strings.NewReader(`{"data":{}}`))
	duplicateOrigin.Header.Add("Origin", fixture.binding.Origin)
	duplicateOrigin.Header.Add("Origin", fixture.binding.Origin)
	duplicateOrigin.Header.Set("Content-Type", "application/json")
	duplicateOrigin.Header.Set("Idempotency-Key", "fedcba0987654321")
	duplicateResponse := httptest.NewRecorder()
	fixture.engine.ServeHTTP(duplicateResponse, duplicateOrigin, fixture.binding)
	assertProblem(t, duplicateResponse, http.StatusForbidden, "forbidden/")
	response = fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents", `{"data":{}}`, map[string]string{
		"Origin": "https://attacker@site.example.test", "Content-Type": "application/json", "Idempotency-Key": "fedcba0987654321",
	})
	assertProblem(t, response, http.StatusForbidden, "forbidden/")
	response = fixture.request(http.MethodPatch, "/_wispist/v1/collections/items/documents/"+document.ID, "", nil)
	assertProblem(t, response, http.StatusMethodNotAllowed, "method-not-allowed/")
	if response.Header().Get("Allow") != "GET, HEAD, PUT, DELETE" {
		t.Fatalf("Allow = %q", response.Header().Get("Allow"))
	}
	response = fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents", `{"data":{"same":1,"same":2}}`, headers)
	assertProblem(t, response, http.StatusBadRequest, "invalid-json/")
	response = fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents", `{"data":{}}`, map[string]string{
		"Origin": "https://site.example.test", "Idempotency-Key": "abcdefghijklmnop",
	})
	assertProblem(t, response, http.StatusUnsupportedMediaType, "unsupported-media-type/")
}

func TestEngineHEADSuppressesProblemBody(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	response := fixture.request(http.MethodHead, "/_wispist/v1/collections/items/documents/missing", "", nil)
	if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
		t.Fatalf("HEAD response = %d, body %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("HEAD content type = %q", response.Header().Get("Content-Type"))
	}
}

func TestEngineRejectsAmbiguousHTTPMetadata(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())

	nonCanonical := httptest.NewRequest(http.MethodGet, "https://site.example.test/_wispist/%76%31", nil)
	nonCanonicalResponse := httptest.NewRecorder()
	fixture.engine.ServeHTTP(nonCanonicalResponse, nonCanonical, fixture.binding)
	assertProblem(t, nonCanonicalResponse, http.StatusBadRequest, "invalid-request/")

	malformedQuery := fixture.request(http.MethodGet, "/_wispist/v1/collections/items/documents?after=%zz", "", nil)
	assertProblem(t, malformedQuery, http.StatusBadRequest, "invalid-request/")

	queryOnCreate := fixture.request(http.MethodPost, "/_wispist/v1/collections/items/documents?ignored=true", `{"data":{}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "Idempotency-Key": "1234567890abcdef",
	})
	assertProblem(t, queryOnCreate, http.StatusBadRequest, "invalid-request/")

	invalidPrecondition := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/item", `{"data":{}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-Match": "not-an-etag",
	})
	assertProblem(t, invalidPrecondition, http.StatusBadRequest, "invalid-request/")

	duplicatePrecondition := httptest.NewRequest(http.MethodPut,
		"https://site.example.test/_wispist/v1/collections/items/documents/item", strings.NewReader(`{"data":{}}`))
	duplicatePrecondition.Header.Set("Origin", fixture.binding.Origin)
	duplicatePrecondition.Header.Set("Content-Type", "application/json")
	duplicatePrecondition.Header.Add("If-Match", `"first-revision-token"`)
	duplicatePrecondition.Header.Add("If-Match", `"second-revision-token"`)
	duplicateResponse := httptest.NewRecorder()
	fixture.engine.ServeHTTP(duplicateResponse, duplicatePrecondition, fixture.binding)
	assertProblem(t, duplicateResponse, http.StatusBadRequest, "invalid-request/")

	badAccept := fixture.request(http.MethodGet, "/_wispist/v1/changes?collections=items", "", map[string]string{
		"Accept": "application/text/event-streamish",
	})
	assertProblem(t, badAccept, http.StatusBadRequest, "invalid-request/")
}

func TestEngineReadOnlyBindingOverridesSharedPolicy(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	fixture.binding.ReadOnly = true
	response := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/fixed", `{"data":{"done":false}}`, map[string]string{
		"Origin": "https://site.example.test", "Content-Type": "application/json", "If-None-Match": "*",
	})
	assertProblem(t, response, http.StatusForbidden, "forbidden/")
}

func TestEngineUpdateDoesNotCreateMissingStore(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	response := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/missing", `{"data":{"done":true}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-Match": `"stale-revision-token"`,
	})
	assertProblem(t, response, http.StatusNotFound, "not-found/")
	if _, err := os.Stat(fixture.dataDirectory); !os.IsNotExist(err) {
		t.Fatalf("failed update created store directory: %v", err)
	}
}

func TestEngineReturnsAuthenticationRequiredForAnonymousPolicy(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	policy := fixture.binding.Declaration.Collections["items"]
	policy.Access[wispist.OperationList] = wispist.AccessAuthenticated
	fixture.binding.Declaration.Collections["items"] = policy
	response := fixture.request(http.MethodGet, "/_wispist/v1/collections/items/documents", "", nil)
	assertProblem(t, response, http.StatusUnauthorized, "authentication-required/")
	if response.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("authentication problem omitted WWW-Authenticate")
	}
}

func TestEngineDoesNotRevealMissingDocumentBeforeAuthorization(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	policy := fixture.binding.Declaration.Collections["items"]
	policy.Access[wispist.OperationRead] = wispist.AccessNobody
	policy.Access[wispist.OperationUpdate] = wispist.AccessNobody
	policy.Access[wispist.OperationDelete] = wispist.AccessNobody
	fixture.binding.Declaration.Collections["items"] = policy

	read := fixture.request(http.MethodGet, "/_wispist/v1/collections/items/documents/missing", "", nil)
	assertProblem(t, read, http.StatusForbidden, "forbidden/")
	update := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/missing", `{"data":{}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-Match": `"missing-revision-token"`,
	})
	assertProblem(t, update, http.StatusForbidden, "forbidden/")
	deleteResponse := fixture.request(http.MethodDelete, "/_wispist/v1/collections/items/documents/missing", "", map[string]string{
		"Origin": fixture.binding.Origin, "If-Match": `"missing-revision-token"`,
	})
	assertProblem(t, deleteResponse, http.StatusForbidden, "forbidden/")
	if _, err := os.Stat(fixture.dataDirectory); !os.IsNotExist(err) {
		t.Fatalf("denied missing operations created store directory: %v", err)
	}
}

type captureAuthorizer struct {
	mu       sync.Mutex
	requests []wispist.AuthorizationRequest
}

type selectiveStreamAuthorizer struct{}

func (selectiveStreamAuthorizer) Authorize(_ context.Context, request wispist.AuthorizationRequest) wispist.AuthorizationDecision {
	if request.Operation != wispist.OperationRead || request.Current == nil {
		return wispist.AuthorizationDecision{Allowed: true}
	}
	return wispist.AuthorizationDecision{Allowed: request.DocumentID == "visible"}
}

func (authorizer *captureAuthorizer) Authorize(_ context.Context, request wispist.AuthorizationRequest) wispist.AuthorizationDecision {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.requests = append(authorizer.requests, request)
	return wispist.AuthorizationDecision{Allowed: true}
}

func TestEngineSuppliesCurrentAndProposedDocumentsToAuthorizer(t *testing.T) {
	t.Parallel()
	authorizer := &captureAuthorizer{}
	fixture := newHTTPFixtureWithAuthorizer(t, wispist.DefaultRateLimits(), authorizer)
	createdResponse := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/item", `{"data":{"done":false}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-None-Match": "*",
	})
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("create = %d, %s", createdResponse.Code, createdResponse.Body.String())
	}
	created := decodeDocument(t, createdResponse)
	updatedResponse := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/item", `{"data":{"done":true}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-Match": `"` + created.Revision + `"`,
	})
	if updatedResponse.Code != http.StatusOK {
		t.Fatalf("update = %d, %s", updatedResponse.Code, updatedResponse.Body.String())
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	var update *wispist.AuthorizationRequest
	for index := range authorizer.requests {
		if authorizer.requests[index].Operation == wispist.OperationUpdate {
			update = &authorizer.requests[index]
		}
	}
	if update == nil || update.Current == nil || update.Current.Revision != created.Revision || string(update.Proposed) != `{"done":true}` {
		t.Fatalf("update authorization request = %+v", update)
	}
}

func TestEngineRateLimitReturnsRetryAfter(t *testing.T) {
	t.Parallel()
	rates := wispist.DefaultRateLimits()
	rates.ReadBurst = 1
	rates.ReadsPerMinute = 1
	fixture := newHTTPFixture(t, rates)
	if response := fixture.request(http.MethodGet, "/_wispist/v1", "", nil); response.Code != http.StatusOK {
		t.Fatalf("first read = %d", response.Code)
	}
	response := fixture.request(http.MethodGet, "/_wispist/v1", "", nil)
	assertProblem(t, response, http.StatusTooManyRequests, "rate-limited/")
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
	}
}

func TestEngineSSEDeliversCommittedChange(t *testing.T) {
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	createResponse := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/shared", `{"data":{"done":false}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-None-Match": "*",
	})
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create = %d, %s", createResponse.Code, createResponse.Body.String())
	}
	document := decodeDocument(t, createResponse)

	listResponse := fixture.request(http.MethodGet, "/_wispist/v1/collections/items/documents", "", nil)
	var page struct {
		Changes string `json:"changes"`
	}
	if err := json.NewDecoder(listResponse.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}
	streamContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	streamRequest := httptest.NewRequest(http.MethodGet, "https://site.example.test/_wispist/v1/changes?collections=items&after="+url.QueryEscape(page.Changes), nil).WithContext(streamContext)
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamResponse := newStreamRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.engine.ServeHTTP(streamResponse, streamRequest, fixture.binding)
	}()
	select {
	case <-streamResponse.activity:
	case <-time.After(time.Second):
		t.Fatal("change stream did not start")
	}
	if streamResponse.statusCode() != http.StatusOK || streamResponse.contentType() != "text/event-stream" {
		t.Fatalf("stream = %d, %q", streamResponse.statusCode(), streamResponse.contentType())
	}

	updateResponse := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/shared", `{"data":{"done":true}}`, map[string]string{
		"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-Match": `"` + document.Revision + `"`,
	})
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update = %d, %s", updateResponse.Code, updateResponse.Body.String())
	}
	deadline := time.After(time.Second)
	for {
		body := streamResponse.bodyString()
		if strings.Contains(body, "event: change\n") && strings.Contains(body, `"operation":"update"`) {
			break
		}
		select {
		case <-streamResponse.activity:
		case <-deadline:
			t.Fatalf("change event not delivered: %q", body)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("change stream did not stop after cancellation")
	}
}

func TestEngineSSEAppliesReadAuthorizationToDeliveredDocuments(t *testing.T) {
	fixture := newHTTPFixtureWithAuthorizer(t, wispist.DefaultRateLimits(), selectiveStreamAuthorizer{})
	for _, id := range []string{"visible", "hidden"} {
		response := fixture.request(http.MethodPut, "/_wispist/v1/collections/items/documents/"+id, `{"data":{"id":"`+id+`"}}`, map[string]string{
			"Origin": fixture.binding.Origin, "Content-Type": "application/json", "If-None-Match": "*",
		})
		if response.Code != http.StatusCreated {
			t.Fatalf("create %s = %d, %s", id, response.Code, response.Body.String())
		}
	}

	streamContext, cancel := context.WithCancel(context.Background())
	streamRequest := httptest.NewRequest(http.MethodGet,
		"https://site.example.test/_wispist/v1/changes?collections=items&after="+url.QueryEscape(wispist.EncodeChangeCursor("live", 0)), nil,
	).WithContext(streamContext)
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamResponse := newStreamRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.engine.ServeHTTP(streamResponse, streamRequest, fixture.binding)
	}()
	deadline := time.After(time.Second)
	for {
		body := streamResponse.bodyString()
		if strings.Contains(body, `"id":"visible"`) {
			if strings.Contains(body, `"id":"hidden"`) {
				t.Fatalf("hidden document was streamed: %q", body)
			}
			break
		}
		select {
		case <-streamResponse.activity:
		case <-deadline:
			t.Fatalf("visible document was not streamed: %q", body)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("change stream did not stop after cancellation")
	}
}

func TestEngineSSEDoesNotCreateAnUntouchedStore(t *testing.T) {
	t.Parallel()
	fixture := newHTTPFixture(t, wispist.DefaultRateLimits())
	streamContext, cancel := context.WithCancel(context.Background())
	streamRequest := httptest.NewRequest(http.MethodGet,
		"https://site.example.test/_wispist/v1/changes?after="+
			url.QueryEscape(wispist.EncodeChangeCursor("live", 0))+"&collections=items", nil,
	).WithContext(streamContext)
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamResponse := newStreamRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.engine.ServeHTTP(streamResponse, streamRequest, fixture.binding)
	}()
	select {
	case <-streamResponse.activity:
	case <-time.After(time.Second):
		t.Fatal("change stream did not start")
	}
	if _, err := os.Stat(fixture.dataDirectory); !os.IsNotExist(err) {
		t.Fatalf("subscription created untouched store directory: %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("change stream did not stop after cancellation")
	}
}

type streamRecorder struct {
	mu       sync.Mutex
	header   http.Header
	status   int
	body     bytes.Buffer
	activity chan struct{}
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{header: make(http.Header), activity: make(chan struct{}, 1)}
}

func (recorder *streamRecorder) Header() http.Header { return recorder.header }

func (recorder *streamRecorder) WriteHeader(status int) {
	recorder.mu.Lock()
	if recorder.status == 0 {
		recorder.status = status
	}
	recorder.mu.Unlock()
}

func (recorder *streamRecorder) Write(body []byte) (int, error) {
	recorder.mu.Lock()
	if recorder.status == 0 {
		recorder.status = http.StatusOK
	}
	written, err := recorder.body.Write(body)
	recorder.mu.Unlock()
	recorder.notify()
	return written, err
}

func (recorder *streamRecorder) Flush() { recorder.notify() }

func (recorder *streamRecorder) notify() {
	select {
	case recorder.activity <- struct{}{}:
	default:
	}
}

func (recorder *streamRecorder) statusCode() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.status
}

func (recorder *streamRecorder) contentType() string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.header.Get("Content-Type")
}

func (recorder *streamRecorder) bodyString() string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.body.String()
}
