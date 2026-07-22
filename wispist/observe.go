package wispist

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type observedResponseWriter struct {
	http.ResponseWriter
	status      int
	problemType string
}

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *observedResponseWriter) recordProblem(value string) { w.problemType = value }

func recordProblemType(w http.ResponseWriter, value string) {
	for range 8 {
		if recorder, ok := w.(interface{ recordProblem(string) }); ok {
			recorder.recordProblem(value)
			return
		}
		wrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = wrapper.Unwrap()
	}
}

func requestOperation(r *http.Request) string {
	switch r.URL.Path {
	case "/_wispist/client/v1.js":
		return "client"
	case apiPrefix:
		return "describe"
	case apiPrefix + "/changes":
		return string(OperationSubscribe)
	}
	if !strings.HasPrefix(r.URL.Path, apiPrefix+"/collections/") {
		return "unknown"
	}
	segments := strings.Split(strings.TrimPrefix(r.URL.Path, apiPrefix+"/"), "/")
	if len(segments) == 3 {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return string(OperationList)
		case http.MethodPost:
			return string(OperationCreate)
		}
	}
	if len(segments) == 4 {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return string(OperationRead)
		case http.MethodPut:
			if r.Header.Get("If-None-Match") == "*" {
				return string(OperationCreate)
			}
			return string(OperationUpdate)
		case http.MethodDelete:
			return string(OperationDelete)
		}
	}
	return "unknown"
}

func (e *Engine) finishRequestObservation(ctx context.Context, binding Binding, operation string, started time.Time, writer *observedResponseWriter) {
	status := writer.status
	if status == 0 {
		status = http.StatusOK
	}
	duration := time.Since(started)
	observation := Observation{
		Event: ObservationRequest, Operation: operation, Mode: safeObservationMode(binding.Mode),
		Status: status, ProblemType: writer.problemType, Duration: duration,
	}
	e.logger.DebugContext(ctx, "Wispist request",
		"operation", observation.Operation, "mode", observation.Mode,
		"status", observation.Status, "problem_type", observation.ProblemType,
		"duration", observation.Duration,
	)
	e.emitObservation(ctx, observation)
}

func safeObservationMode(mode Mode) Mode {
	if mode == ModeLive || mode == ModeDraft || mode == ModeLivePreview {
		return mode
	}
	return "invalid"
}

func (e *Engine) emitObservation(ctx context.Context, observation Observation) {
	if e.observer == nil {
		return
	}
	defer func() {
		if recover() != nil {
			e.logger.ErrorContext(ctx, "Wispist observer panicked")
		}
	}()
	e.observer.Observe(ctx, observation)
}
