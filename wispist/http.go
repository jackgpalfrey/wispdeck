package wispist

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const apiPrefix = "/_wispist/v1"

type wireDocument struct {
	ID        string          `json:"id"`
	Revision  string          `json:"revision"`
	CreatedAt string          `json:"createdAt"`
	UpdatedAt string          `json:"updatedAt"`
	Data      json.RawMessage `json:"data"`
}

type dataEnvelope struct {
	Data json.RawMessage `json:"data"`
}

// headResponseWriter preserves the headers and status of the corresponding GET
// response while suppressing every response body, including Problem Details.
type headResponseWriter struct {
	http.ResponseWriter
}

func (w headResponseWriter) Write(body []byte) (int, error) { return len(body), nil }

func (w headResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request, binding Binding) {
	started := time.Now()
	observed := &observedResponseWriter{ResponseWriter: w}
	w = observed
	defer e.finishRequestObservation(r.Context(), binding, requestOperation(r), started, observed)
	if r.Method == http.MethodHead {
		w = headResponseWriter{ResponseWriter: w}
	}
	id := requestID(r)
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if err := e.validateBinding(binding); err != nil {
		e.logger.ErrorContext(r.Context(), "invalid Wispist host binding", "error", err, "request_id", id)
		writeProblem(w, id, problemTemporarilyUnavailable, "")
		return
	}
	clientPath := r.URL.Path == "/_wispist/client/v1.js"
	apiPath := r.URL.Path == apiPrefix || strings.HasPrefix(r.URL.Path, apiPrefix+"/")
	if !clientPath && !apiPath {
		writeProblem(w, id, problemNotFound, "")
		return
	}
	if !canonicalAPIPath(r.URL) {
		writeProblem(w, id, problemInvalidRequest, "The API path is not canonical.")
		return
	}
	if clientPath {
		if !e.allowRequest(w, binding, false, false) {
			return
		}
		e.serveClient(w, r, id)
		return
	}
	if r.URL.Path == apiPrefix {
		if !e.allowRequest(w, binding, r.Method != http.MethodGet && r.Method != http.MethodHead, false) {
			return
		}
		e.serveDescription(w, r, binding, id)
		return
	}
	if r.URL.Path == apiPrefix+"/changes" {
		if !e.allowRequest(w, binding, false, false) {
			return
		}
		e.serveChanges(w, r, binding, id)
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, apiPrefix+"/")
	segments := strings.Split(remainder, "/")
	if len(segments) != 3 && len(segments) != 4 || segments[0] != "collections" || segments[2] != "documents" {
		writeProblem(w, id, problemNotFound, "")
		return
	}
	collection := segments[1]
	if !ValidCollectionName(collection) {
		writeProblem(w, id, problemInvalidRequest, "The collection name is invalid.")
		return
	}
	if _, ok := binding.Declaration.Collections[collection]; !ok {
		writeProblem(w, id, problemNotFound, "")
		return
	}
	if len(segments) == 3 {
		mutation := r.Method != http.MethodGet && r.Method != http.MethodHead
		if !e.allowRequest(w, binding, mutation, mutation && r.Method == http.MethodPost) {
			return
		}
		e.serveCollection(w, r, binding, id, collection)
		return
	}
	documentID, err := url.PathUnescape(segments[3])
	if err != nil || documentID != segments[3] || !ValidDocumentID(documentID) {
		writeProblem(w, id, problemInvalidRequest, "The document ID is invalid.")
		return
	}
	mutation := r.Method != http.MethodGet && r.Method != http.MethodHead
	if !e.allowRequest(w, binding, mutation, false) {
		return
	}
	e.serveDocument(w, r, binding, id, collection, documentID)
}

func (e *Engine) serveClient(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, id, problemMethodNotAllowed, "The client resource supports only GET and HEAD.")
		return
	}
	if hasQuery(r) {
		writeProblem(w, id, problemInvalidRequest, "The client resource does not accept query parameters.")
		return
	}
	etag := `"` + hex.EncodeToString(e.clientDigest[:]) + `"`
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("ETag", etag)
	if ifNoneMatch(strings.Join(r.Header.Values("If-None-Match"), ","), hex.EncodeToString(e.clientDigest[:])) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(e.client)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(e.client)
}

func (e *Engine) serveDescription(w http.ResponseWriter, r *http.Request, binding Binding, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeProblem(w, id, problemMethodNotAllowed, "The service description supports only GET and HEAD.")
		return
	}
	if hasQuery(r) {
		writeProblem(w, id, problemInvalidRequest, "The service description does not accept query parameters.")
		return
	}
	collections := make([]string, 0, len(binding.Declaration.Collections))
	for collection := range binding.Declaration.Collections {
		collections = append(collections, collection)
	}
	sort.Strings(collections)
	e.writeJSON(w, r, http.StatusOK, map[string]any{
		"name": "Wispist", "version": ProtocolVersion, "mode": binding.Mode,
		"readOnly": binding.ReadOnly, "collections": collections,
	})
}

func (e *Engine) serveCollection(w http.ResponseWriter, r *http.Request, binding Binding, id, collection string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		e.listDocuments(w, r, binding, id, collection)
	case http.MethodPost:
		e.createDocument(w, r, binding, id, collection)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		writeProblem(w, id, problemMethodNotAllowed, "The collection does not support this method.")
	}
}

func (e *Engine) serveDocument(w http.ResponseWriter, r *http.Request, binding Binding, id, collection, documentID string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		e.getDocument(w, r, binding, id, collection, documentID)
	case http.MethodPut:
		e.putDocument(w, r, binding, id, collection, documentID)
	case http.MethodDelete:
		e.deleteDocument(w, r, binding, id, collection, documentID)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		writeProblem(w, id, problemMethodNotAllowed, "The document does not support this method.")
	}
}

func (e *Engine) listDocuments(w http.ResponseWriter, r *http.Request, binding Binding, id, collection string) {
	if !e.authorize(w, r, binding, id, OperationList, collection, "", nil, nil) {
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeProblem(w, id, problemInvalidRequest, "The list query is malformed.")
		return
	}
	for key := range query {
		if key != "limit" && key != "after" {
			writeProblem(w, id, problemInvalidRequest, "The list query contains an unknown parameter.")
			return
		}
		if len(query[key]) != 1 {
			writeProblem(w, id, problemInvalidRequest, "A list query parameter was repeated.")
			return
		}
	}
	limit := e.limits.DefaultListLimit
	if values, present := query["limit"]; present {
		value := values[0]
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > e.limits.MaxListLimit {
			writeProblem(w, id, problemInvalidRequest, "The list limit is invalid.")
			return
		}
		limit = parsed
	}
	if values, present := query["after"]; present && values[0] == "" {
		writeProblem(w, id, problemInvalidRequest, "The pagination cursor is empty.")
		return
	}
	store, err := e.stores.Open(r.Context(), binding.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		e.writeListPage(w, r, wispistEmptyList(binding.Namespace))
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "open store for list", err)
		return
	}
	defer store.Close()
	page, err := store.List(r.Context(), binding.Namespace, collection, limit, query.Get("after"))
	if err != nil {
		e.writeStoreError(w, r, id, "list documents", err)
		return
	}
	e.writeListPage(w, r, page)
}

func wispistEmptyList(namespace string) ListPage {
	return ListPage{Documents: []Document{}, ChangeCursor: EncodeChangeCursor(namespace, 0)}
}

func (e *Engine) writeListPage(w http.ResponseWriter, r *http.Request, page ListPage) {
	documents := make([]wireDocument, len(page.Documents))
	for index := range page.Documents {
		documents[index] = toWireDocument(page.Documents[index])
	}
	var after any
	if page.After != "" {
		after = page.After
	}
	e.writeJSON(w, r, http.StatusOK, map[string]any{
		"documents": documents, "after": after, "changes": page.ChangeCursor,
	})
}

func (e *Engine) createDocument(w http.ResponseWriter, r *http.Request, binding Binding, id, collection string) {
	if e.rejectReadOnlyMutation(w, binding, id) {
		return
	}
	if !validUnsafeOrigin(r, binding.Origin) {
		writeProblem(w, id, problemForbidden, "The request did not come from the bound site origin.")
		return
	}
	if hasQuery(r) {
		writeProblem(w, id, problemInvalidRequest, "The collection resource does not accept query parameters.")
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		writeProblem(w, id, problemInvalidRequest, "Exactly one Idempotency-Key is required.")
		return
	}
	key := keys[0]
	if !validIdempotencyKey(key) {
		writeProblem(w, id, problemInvalidRequest, "Idempotency-Key must contain 16 to 128 visible ASCII characters.")
		return
	}
	policy := binding.Declaration.Collections[collection]
	data, ok := e.readDataEnvelope(w, r, id, policy.MaxDocumentBytes)
	if !ok {
		return
	}
	if !e.authorize(w, r, binding, id, OperationCreate, collection, "", nil, data) {
		return
	}
	store, err := e.stores.Open(r.Context(), binding.StoreKey, true)
	if err != nil {
		e.writeStoreError(w, r, id, "open store for create", err)
		return
	}
	defer store.Close()
	fingerprint := sha256.Sum256(append([]byte(r.Method+"\x00"+r.URL.Path+"\x00"), data...))
	var document Document
	var change Change
	var replay bool
	for attempt := 0; attempt < 3; attempt++ {
		documentID, generateErr := newDocumentID()
		if generateErr != nil {
			e.writeStoreError(w, r, id, "generate document ID", generateErr)
			return
		}
		document, change, replay, err = store.Create(r.Context(), CreateRequest{
			Namespace: binding.Namespace, Collection: collection, ID: documentID, Data: data,
			IdempotencyKey: key, Fingerprint: fingerprint, Now: e.now().UTC(),
			Limits: e.mutationLimits(binding, policy),
		})
		if !errors.Is(err, ErrRevisionConflict) {
			break
		}
	}
	if err != nil {
		e.writeStoreError(w, r, id, "create document", err)
		return
	}
	if !replay {
		e.hub.publish(hubNamespace(binding), change)
	}
	w.Header().Set("Location", r.URL.Path+"/"+document.ID)
	e.writeDocument(w, r, http.StatusCreated, document)
}

func (e *Engine) getDocument(w http.ResponseWriter, r *http.Request, binding Binding, id, collection, documentID string) {
	if hasQuery(r) {
		writeProblem(w, id, problemInvalidRequest, "The document resource does not accept query parameters.")
		return
	}
	store, err := e.stores.Open(r.Context(), binding.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		e.writeMissingAfterAuthorization(w, r, binding, id, OperationRead, collection, documentID, nil)
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "open store for read", err)
		return
	}
	defer store.Close()
	document, err := store.Get(r.Context(), binding.Namespace, collection, documentID)
	if errors.Is(err, ErrDocumentNotFound) {
		e.writeMissingAfterAuthorization(w, r, binding, id, OperationRead, collection, documentID, nil)
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "read document", err)
		return
	}
	if !e.authorize(w, r, binding, id, OperationRead, collection, documentID, &document, nil) {
		return
	}
	if ifNoneMatch(strings.Join(r.Header.Values("If-None-Match"), ","), document.Revision) {
		w.Header().Set("ETag", quoteETag(document.Revision))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	e.writeDocument(w, r, http.StatusOK, document)
}

func (e *Engine) putDocument(w http.ResponseWriter, r *http.Request, binding Binding, id, collection, documentID string) {
	if e.rejectReadOnlyMutation(w, binding, id) {
		return
	}
	if !validUnsafeOrigin(r, binding.Origin) {
		writeProblem(w, id, problemForbidden, "The request did not come from the bound site origin.")
		return
	}
	if hasQuery(r) {
		writeProblem(w, id, problemInvalidRequest, "The document resource does not accept query parameters.")
		return
	}
	ifNoneValues := r.Header.Values("If-None-Match")
	ifMatchValues := r.Header.Values("If-Match")
	if len(ifNoneValues) > 1 || len(ifMatchValues) > 1 {
		writeProblem(w, id, problemInvalidRequest, "A mutation precondition header was repeated.")
		return
	}
	if len(ifNoneValues) == 0 && len(ifMatchValues) == 0 {
		writeProblem(w, id, problemPreconditionRequired, "")
		return
	}
	if len(ifNoneValues) != 0 && len(ifMatchValues) != 0 {
		writeProblem(w, id, problemInvalidRequest, "Use exactly one of If-None-Match or If-Match.")
		return
	}
	createOnly := len(ifNoneValues) == 1
	if createOnly && strings.TrimSpace(ifNoneValues[0]) != "*" {
		writeProblem(w, id, problemInvalidRequest, "If-None-Match must be * for a create.")
		return
	}
	expected := ""
	if !createOnly {
		var ok bool
		expected, ok = parseStrongETag(ifMatchValues[0])
		if !ok {
			writeProblem(w, id, problemInvalidRequest, "If-Match must contain one strong document ETag.")
			return
		}
	}
	policy := binding.Declaration.Collections[collection]
	data, ok := e.readDataEnvelope(w, r, id, policy.MaxDocumentBytes)
	if !ok {
		return
	}
	operation := OperationCreate
	if !createOnly {
		operation = OperationUpdate
	} else if !e.authorize(w, r, binding, id, operation, collection, documentID, nil, data) {
		return
	}
	store, err := e.stores.Open(r.Context(), binding.StoreKey, createOnly)
	if !createOnly && errors.Is(err, ErrStoreNotFound) {
		e.writeMissingAfterAuthorization(w, r, binding, id, operation, collection, documentID, data)
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "open store for replacement", err)
		return
	}
	defer store.Close()
	var current *Document
	if !createOnly {
		value, getErr := store.Get(r.Context(), binding.Namespace, collection, documentID)
		if errors.Is(getErr, ErrDocumentNotFound) {
			e.writeMissingAfterAuthorization(w, r, binding, id, operation, collection, documentID, data)
			return
		}
		if getErr != nil {
			e.writeStoreError(w, r, id, "read document for authorization", getErr)
			return
		}
		current = &value
	}
	if !createOnly && !e.authorize(w, r, binding, id, operation, collection, documentID, current, data) {
		return
	}
	document, change, err := store.Put(r.Context(), PutRequest{
		Namespace: binding.Namespace, Collection: collection, ID: documentID, Data: data,
		CreateOnly: createOnly, ExpectedRevision: expected, Now: e.now().UTC(),
		Limits: e.mutationLimits(binding, policy),
	})
	if err != nil {
		e.writeStoreError(w, r, id, "replace document", err)
		return
	}
	e.hub.publish(hubNamespace(binding), change)
	status := http.StatusOK
	if createOnly {
		status = http.StatusCreated
		w.Header().Set("Location", r.URL.Path)
	}
	e.writeDocument(w, r, status, document)
}

func (e *Engine) deleteDocument(w http.ResponseWriter, r *http.Request, binding Binding, id, collection, documentID string) {
	if e.rejectReadOnlyMutation(w, binding, id) {
		return
	}
	if !validUnsafeOrigin(r, binding.Origin) {
		writeProblem(w, id, problemForbidden, "The request did not come from the bound site origin.")
		return
	}
	if hasQuery(r) {
		writeProblem(w, id, problemInvalidRequest, "The document resource does not accept query parameters.")
		return
	}
	ifMatchValues := r.Header.Values("If-Match")
	if len(ifMatchValues) == 0 {
		writeProblem(w, id, problemPreconditionRequired, "")
		return
	}
	if len(ifMatchValues) != 1 {
		writeProblem(w, id, problemInvalidRequest, "If-Match was repeated.")
		return
	}
	expected, ok := parseStrongETag(ifMatchValues[0])
	if !ok {
		writeProblem(w, id, problemInvalidRequest, "If-Match must contain one strong document ETag.")
		return
	}
	store, err := e.stores.Open(r.Context(), binding.StoreKey, false)
	if errors.Is(err, ErrStoreNotFound) {
		e.writeMissingAfterAuthorization(w, r, binding, id, OperationDelete, collection, documentID, nil)
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "open store for deletion", err)
		return
	}
	defer store.Close()
	current, err := store.Get(r.Context(), binding.Namespace, collection, documentID)
	if errors.Is(err, ErrDocumentNotFound) {
		e.writeMissingAfterAuthorization(w, r, binding, id, OperationDelete, collection, documentID, nil)
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "read document for deletion authorization", err)
		return
	}
	if !e.authorize(w, r, binding, id, OperationDelete, collection, documentID, &current, nil) {
		return
	}
	policy := binding.Declaration.Collections[collection]
	change, err := store.Delete(r.Context(), DeleteRequest{
		Namespace: binding.Namespace, Collection: collection, ID: documentID,
		ExpectedRevision: expected, Now: e.now().UTC(), Limits: e.mutationLimits(binding, policy),
	})
	if err != nil {
		e.writeStoreError(w, r, id, "delete document", err)
		return
	}
	e.hub.publish(hubNamespace(binding), change)
	w.WriteHeader(http.StatusNoContent)
}

func (e *Engine) authorize(w http.ResponseWriter, r *http.Request, binding Binding, id string, operation Operation, collection, documentID string, current *Document, proposed json.RawMessage) bool {
	if binding.ReadOnly && operation.mutation() {
		writeProblem(w, id, problemForbidden, "This view is read-only.")
		return false
	}
	decision := e.authorizer.Authorize(r.Context(), AuthorizationRequest{
		Binding: binding, Operation: operation, Collection: collection,
		DocumentID: documentID, Current: current, Proposed: proposed,
	})
	if decision.Allowed {
		return true
	}
	if decision.AuthenticationRequired {
		w.Header().Set("WWW-Authenticate", `Wispist realm="site"`)
		writeProblem(w, id, problemAuthenticationRequired, "")
		return false
	}
	writeProblem(w, id, problemForbidden, "")
	return false
}

func (e *Engine) rejectReadOnlyMutation(w http.ResponseWriter, binding Binding, id string) bool {
	if !binding.ReadOnly {
		return false
	}
	writeProblem(w, id, problemForbidden, "This view is read-only.")
	return true
}

func (e *Engine) writeMissingAfterAuthorization(
	w http.ResponseWriter,
	r *http.Request,
	binding Binding,
	id string,
	operation Operation,
	collection string,
	documentID string,
	proposed json.RawMessage,
) {
	if e.authorize(w, r, binding, id, operation, collection, documentID, nil, proposed) {
		writeProblem(w, id, problemNotFound, "")
	}
}

func (e *Engine) readDataEnvelope(w http.ResponseWriter, r *http.Request, id string, maxDocumentBytes int) (json.RawMessage, bool) {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeProblem(w, id, problemUnsupportedMediaType, "")
		return nil, false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		writeProblem(w, id, problemUnsupportedMediaType, "")
		return nil, false
	}
	maxBody := int64(maxDocumentBytes) + e.limits.MaxRequestEnvelopeBytes
	reader := io.LimitReader(r.Body, maxBody+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		writeProblem(w, id, problemInvalidRequest, "The request body could not be read.")
		return nil, false
	}
	if int64(len(body)) > maxBody {
		writeProblem(w, id, problemRequestTooLarge, "")
		return nil, false
	}
	if _, err := normalizeJSONObject(body, int(maxBody), 33, 256); err != nil {
		writeProblem(w, id, problemInvalidJSON, "")
		return nil, false
	}
	var envelope dataEnvelope
	if err := decodeStrict(body, &envelope); err != nil {
		writeProblem(w, id, problemInvalidRequest, "The request must contain only a data member.")
		return nil, false
	}
	data, err := normalizeJSONObject(envelope.Data, maxDocumentBytes, 32, 256)
	if err != nil {
		definition := problemInvalidJSON
		if len(envelope.Data) > maxDocumentBytes {
			definition = problemRequestTooLarge
		}
		writeProblem(w, id, definition, "")
		return nil, false
	}
	return data, true
}

func (e *Engine) writeDocument(w http.ResponseWriter, r *http.Request, status int, document Document) {
	w.Header().Set("ETag", quoteETag(document.Revision))
	e.writeJSON(w, r, status, toWireDocument(document))
}

func (e *Engine) writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		e.logger.ErrorContext(r.Context(), "marshal Wispist response", "error", err)
		writeProblem(w, w.Header().Get("X-Request-ID"), problemTemporarilyUnavailable, "")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(append(body, '\n'))
	}
}

func (e *Engine) writeStoreError(w http.ResponseWriter, r *http.Request, id, operation string, err error) {
	switch {
	case errors.Is(err, ErrStoreNotFound), errors.Is(err, ErrDocumentNotFound):
		writeProblem(w, id, problemNotFound, "")
	case errors.Is(err, ErrRevisionConflict):
		writeProblem(w, id, problemRevisionConflict, "")
	case errors.Is(err, ErrQuotaExceeded):
		writeProblem(w, id, problemQuotaExceeded, "")
	case errors.Is(err, ErrIdempotencyConflict):
		writeProblem(w, id, problemIdempotencyConflict, "")
	case errors.Is(err, ErrInvalidCursor):
		writeProblem(w, id, problemInvalidRequest, "The cursor is invalid.")
	case errors.Is(err, ErrStoreUnavailable):
		w.Header().Set("Retry-After", "1")
		writeProblem(w, id, problemTemporarilyUnavailable, "")
	default:
		e.logger.ErrorContext(r.Context(), "Wispist store operation failed", "operation", operation, "error", err, "request_id", id)
		writeProblem(w, id, problemTemporarilyUnavailable, "")
	}
}

func toWireDocument(document Document) wireDocument {
	const layout = "2006-01-02T15:04:05.000Z"
	return wireDocument{
		ID: document.ID, Revision: document.Revision,
		CreatedAt: document.CreatedAt.UTC().Format(layout), UpdatedAt: document.UpdatedAt.UTC().Format(layout),
		Data: document.Data,
	}
}

func canonicalAPIPath(value *url.URL) bool {
	if value.Path == "" || value.Path[0] != '/' || strings.Contains(value.Path, "\\") ||
		strings.ContainsRune(value.Path, 0) || pathpkg.Clean(value.Path) != value.Path {
		return false
	}
	canonical := (&url.URL{Path: value.Path}).EscapedPath()
	return value.EscapedPath() == canonical
}

func validUnsafeOrigin(r *http.Request, expected string) bool {
	if len(r.Header.Values("Origin")) != 1 || len(r.Header.Values("Sec-Fetch-Site")) > 1 {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	actual, err := url.Parse(r.Header.Get("Origin"))
	want, wantErr := url.Parse(expected)
	return err == nil && wantErr == nil && actual.User == nil && actual.Opaque == "" &&
		!actual.ForceQuery && strings.EqualFold(actual.Scheme, want.Scheme) &&
		strings.EqualFold(actual.Host, want.Host) && actual.Path == "" && actual.RawPath == "" &&
		actual.RawQuery == "" && actual.Fragment == ""
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, char := range []byte(value) {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

func parseStrongETag(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' ||
		strings.Contains(value, ",") || strings.HasPrefix(value, "W/") {
		return "", false
	}
	revision := value[1 : len(value)-1]
	if len(revision) < 16 || len(revision) > 128 || strings.ContainsAny(revision, "\"\\\r\n") {
		return "", false
	}
	return revision, true
}

func hasQuery(r *http.Request) bool { return r.URL.ForceQuery || r.URL.RawQuery != "" }

func quoteETag(revision string) string { return `"` + revision + `"` }

func ifNoneMatch(value, revision string) bool {
	value = strings.TrimSpace(value)
	if value == "*" {
		return true
	}
	for value != "" {
		value = strings.TrimLeft(value, " \t")
		if strings.HasPrefix(value, "W/") {
			value = value[2:]
		}
		if len(value) < 2 || value[0] != '"' {
			return false
		}
		end := strings.IndexByte(value[1:], '"')
		if end < 0 {
			return false
		}
		end++
		if value[1:end] == revision {
			return true
		}
		value = strings.TrimLeft(value[end+1:], " \t")
		if value == "" {
			return false
		}
		if value[0] != ',' {
			return false
		}
		value = value[1:]
	}
	return false
}

func newDocumentID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate document ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (e *Engine) allowRequest(w http.ResponseWriter, binding Binding, mutation, generated bool) bool {
	allowed, retry := e.limiter.allow(binding, mutation, generated, e.now().UTC())
	if allowed {
		return true
	}
	seconds := int64((retry + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeProblem(w, w.Header().Get("X-Request-ID"), problemRateLimited, "")
	return false
}
