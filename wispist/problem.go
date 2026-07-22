package wispist

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type Problem struct {
	Type     string              `json:"type"`
	Title    string              `json:"title"`
	Status   int                 `json:"status"`
	Detail   string              `json:"detail"`
	Instance string              `json:"instance"`
	Errors   []ProblemFieldError `json:"errors,omitempty"`
}

type ProblemFieldError struct {
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

type problemDefinition struct {
	Suffix string
	Title  string
	Status int
	Detail string
}

var (
	problemInvalidRequest         = problemDefinition{"invalid-request/", "Invalid request", http.StatusBadRequest, "The request is invalid."}
	problemInvalidJSON            = problemDefinition{"invalid-json/", "Invalid JSON", http.StatusBadRequest, "The JSON representation is malformed or not allowed."}
	problemAuthenticationRequired = problemDefinition{"authentication-required/", "Authentication required", http.StatusUnauthorized, "Authentication is required for this operation."}
	problemForbidden              = problemDefinition{"forbidden/", "Forbidden", http.StatusForbidden, "This operation is not permitted."}
	problemNotFound               = problemDefinition{"not-found/", "Not found", http.StatusNotFound, "The requested resource is unavailable."}
	problemIdempotencyConflict    = problemDefinition{"idempotency-conflict/", "Idempotency conflict", http.StatusConflict, "The idempotency key was already used for a different request."}
	problemQuotaExceeded          = problemDefinition{"quota-exceeded/", "Quota exceeded", http.StatusConflict, "The operation would exceed a storage limit."}
	problemRevisionConflict       = problemDefinition{"revision-conflict/", "Revision conflict", http.StatusPreconditionFailed, "The document changed after it was read."}
	problemRequestTooLarge        = problemDefinition{"request-too-large/", "Request too large", http.StatusRequestEntityTooLarge, "The request exceeds its permitted size."}
	problemUnsupportedMediaType   = problemDefinition{"unsupported-media-type/", "Unsupported media type", http.StatusUnsupportedMediaType, "This operation requires application/json."}
	problemMethodNotAllowed       = problemDefinition{"method-not-allowed/", "Method not allowed", http.StatusMethodNotAllowed, "This resource does not support the request method."}
	problemPreconditionRequired   = problemDefinition{"precondition-required/", "Precondition required", http.StatusPreconditionRequired, "This mutation requires an HTTP precondition."}
	problemRateLimited            = problemDefinition{"rate-limited/", "Rate limited", http.StatusTooManyRequests, "Too many requests were made in a short period."}
	problemTemporarilyUnavailable = problemDefinition{"temporarily-unavailable/", "Temporarily unavailable", http.StatusServiceUnavailable, "Wispist is temporarily unavailable."}
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func requestID(request *http.Request) string {
	if value := request.Header.Get("X-Request-ID"); uuidPattern.MatchString(value) {
		return value
	}
	value, err := newUUID()
	if err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	return value
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func writeProblem(w http.ResponseWriter, id string, definition problemDefinition, detail string, fieldErrors ...ProblemFieldError) {
	if detail == "" {
		detail = definition.Detail
	}
	problem := Problem{
		Type: ProblemBaseURL + definition.Suffix, Title: definition.Title,
		Status: definition.Status, Detail: detail, Instance: "urn:uuid:" + id,
		Errors: fieldErrors,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/problem+json")
	recordProblemType(w, ProblemBaseURL+definition.Suffix)
	w.WriteHeader(definition.Status)
	_ = json.NewEncoder(w).Encode(problem)
}
