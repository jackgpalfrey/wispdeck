package wispist

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type wireChange struct {
	Collection string          `json:"collection"`
	Operation  ChangeOperation `json:"operation"`
	Document   *wireDocument   `json:"document,omitempty"`
	ID         string          `json:"id,omitempty"`
	Revision   string          `json:"revision,omitempty"`
}

func (e *Engine) serveChanges(w http.ResponseWriter, r *http.Request, binding Binding, id string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeProblem(w, id, problemMethodNotAllowed, "The change stream supports only GET.")
		return
	}
	if !acceptsEventStream(r.Header.Values("Accept")) {
		writeProblem(w, id, problemInvalidRequest, "The change stream requires Accept: text/event-stream.")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeProblem(w, id, problemInvalidRequest, "The change query is malformed.")
		return
	}
	for key := range query {
		if key != "collections" && key != "after" {
			writeProblem(w, id, problemInvalidRequest, "The change query contains an unknown parameter.")
			return
		}
	}
	if len(query["after"]) > 1 {
		writeProblem(w, id, problemInvalidRequest, "The change cursor was repeated.")
		return
	}
	if len(query["after"]) == 1 && query["after"][0] == "" {
		writeProblem(w, id, problemInvalidRequest, "The change cursor is empty.")
		return
	}
	seen := make(map[string]struct{})
	collections := make([]string, 0, len(query["collections"]))
	for _, collection := range query["collections"] {
		if !ValidCollectionName(collection) {
			writeProblem(w, id, problemInvalidRequest, "A subscribed collection name is invalid.")
			return
		}
		if _, declared := binding.Declaration.Collections[collection]; !declared {
			writeProblem(w, id, problemNotFound, "")
			return
		}
		if _, duplicate := seen[collection]; duplicate {
			continue
		}
		seen[collection] = struct{}{}
		collections = append(collections, collection)
	}
	if len(collections) < 1 || len(collections) > e.limits.MaxSubscribedCollections {
		writeProblem(w, id, problemInvalidRequest, "The number of subscribed collections is invalid.")
		return
	}
	sort.Strings(collections)
	for _, collection := range collections {
		if !e.authorize(w, r, binding, id, OperationSubscribe, collection, "", nil, nil) ||
			!e.authorize(w, r, binding, id, OperationRead, collection, "", nil, nil) {
			return
		}
	}
	releaseStream, allowed := e.limiter.acquireStream(binding)
	if !allowed {
		w.Header().Set("Retry-After", "1")
		writeProblem(w, id, problemRateLimited, "Too many change streams are already open for this site or client.")
		return
	}
	defer releaseStream()
	e.emitObservation(r.Context(), Observation{
		Event: ObservationStream, Operation: string(OperationSubscribe), Mode: binding.Mode, Delta: 1,
	})
	defer e.emitObservation(r.Context(), Observation{
		Event: ObservationStream, Operation: string(OperationSubscribe), Mode: binding.Mode, Delta: -1,
	})

	events, unsubscribe := e.hub.subscribe(hubNamespace(binding), collections)
	defer unsubscribe()
	store, err := e.stores.Open(r.Context(), binding.StoreKey, false)
	storeMissing := errors.Is(err, ErrStoreNotFound)
	if err != nil && !storeMissing {
		e.writeStoreError(w, r, id, "open store for subscription", err)
		return
	}
	if store != nil {
		defer store.Close()
	}
	after := query.Get("after")
	if after == "" && storeMissing {
		after = EncodeChangeCursor(binding.Namespace, 0)
	} else if after == "" {
		after, err = store.HighWater(r.Context(), binding.Namespace)
		if err != nil {
			e.writeStoreError(w, r, id, "read subscription high-water mark", err)
			return
		}
	}
	page := ChangesPage{Cursor: after}
	if storeMissing {
		sequence, decodeErr := DecodeChangeCursor(binding.Namespace, after)
		if decodeErr != nil {
			writeProblem(w, id, problemInvalidRequest, "The cursor is invalid.")
			return
		}
		if sequence != 0 {
			e.startSSE(w)
			_ = e.writeSSEReset(r, w, binding, "cursor_expired")
			return
		}
	} else {
		page, err = store.Changes(r.Context(), binding.Namespace, collections, after, e.limits.MaxListLimit)
	}
	if errors.Is(err, ErrCursorExpired) {
		e.startSSE(w)
		_ = e.writeSSEReset(r, w, binding, "cursor_expired")
		return
	}
	if err != nil {
		e.writeStoreError(w, r, id, "read subscription backlog", err)
		return
	}
	e.startSSE(w)
	lastSequence, err := DecodeChangeCursor(binding.Namespace, after)
	if err != nil {
		_ = e.writeSSEReset(r, w, binding, "invalid_cursor")
		return
	}
	for {
		for _, change := range page.Changes {
			if change.Sequence <= lastSequence {
				continue
			}
			if !e.canReadChange(r, binding, change) {
				lastSequence = change.Sequence
				continue
			}
			if err := e.writeSSEChange(w, change); err != nil {
				return
			}
			lastSequence = change.Sequence
		}
		cursorSequence, decodeErr := DecodeChangeCursor(binding.Namespace, page.Cursor)
		if decodeErr != nil {
			_ = e.writeSSEReset(r, w, binding, "invalid_cursor")
			return
		}
		if cursorSequence > lastSequence {
			lastSequence = cursorSequence
		}
		if !page.More {
			break
		}
		page, err = store.Changes(r.Context(), binding.Namespace, collections, page.Cursor, e.limits.MaxListLimit)
		if err != nil {
			_ = e.writeSSEReset(r, w, binding, "backlog_unavailable")
			return
		}
	}

	heartbeat := time.NewTicker(e.limits.SSEHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok {
				_ = e.writeSSEReset(r, w, binding, "slow_consumer")
				return
			}
			if event.ResetReason != "" {
				_ = e.writeSSEReset(r, w, binding, event.ResetReason)
				return
			}
			if event.Change.Sequence <= lastSequence {
				continue
			}
			if !e.canReadChange(r, binding, event.Change) {
				lastSequence = event.Change.Sequence
				continue
			}
			if err := e.writeSSEChange(w, event.Change); err != nil {
				return
			}
			lastSequence = event.Change.Sequence
		case <-heartbeat.C:
			if err := setSSEWriteDeadline(w, e.limits.SSEHeartbeat); err != nil {
				return
			}
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if err := flushSSE(w); err != nil {
				return
			}
		}
	}
}

func (e *Engine) canReadChange(r *http.Request, binding Binding, change Change) bool {
	documentID := change.ID
	if change.Document != nil {
		documentID = change.Document.ID
	}
	return e.authorizer.Authorize(r.Context(), AuthorizationRequest{
		Binding: binding, Operation: OperationRead, Collection: change.Collection,
		DocumentID: documentID, Current: change.Document,
	}).Allowed
}

func (e *Engine) writeSSEReset(r *http.Request, w http.ResponseWriter, binding Binding, reason string) error {
	e.emitObservation(r.Context(), Observation{
		Event: ObservationStreamReset, Operation: string(OperationSubscribe), Mode: binding.Mode, Reason: reason,
	})
	return e.writeSSE(w, "", "reset", map[string]string{"reason": reason})
}

func (e *Engine) startSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_ = flushSSE(w)
}

func (e *Engine) writeSSEChange(w http.ResponseWriter, change Change) error {
	payload := wireChange{
		Collection: change.Collection, Operation: change.Operation,
		ID: change.ID, Revision: change.Revision,
	}
	if change.Document != nil {
		document := toWireDocument(*change.Document)
		payload.Document = &document
		payload.ID = ""
		payload.Revision = ""
	}
	return e.writeSSE(w, change.Cursor, "change", payload)
}

func (e *Engine) writeSSE(w http.ResponseWriter, cursor, event string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := setSSEWriteDeadline(w, e.limits.SSEHeartbeat); err != nil {
		return err
	}
	if cursor != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", cursor); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body); err != nil {
		return err
	}
	return flushSSE(w)
}

func flushSSE(w http.ResponseWriter) error {
	err := http.NewResponseController(w).Flush()
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func acceptsEventStream(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			mediaType, parameters, err := mime.ParseMediaType(strings.TrimSpace(candidate))
			if err != nil {
				continue
			}
			if quality, present := parameters["q"]; present {
				parsed, parseErr := strconv.ParseFloat(quality, 64)
				if parseErr != nil || parsed <= 0 || parsed > 1 {
					continue
				}
			}
			if mediaType == "text/event-stream" || mediaType == "text/*" || mediaType == "*/*" {
				return true
			}
		}
	}
	return false
}

func setSSEWriteDeadline(w http.ResponseWriter, heartbeat time.Duration) error {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(heartbeat + 10*time.Second))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}
