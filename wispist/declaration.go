package wispist

import (
	"encoding/json"
	"errors"
	"fmt"
)

const MaxDeclarationBytes = 64 << 10

var ErrInvalidDeclaration = errors.New("invalid wispist.json")

type rawDeclaration struct {
	Version     int                      `json:"version"`
	Collections map[string]rawCollection `json:"collections"`
}

type rawCollection struct {
	Access json.RawMessage     `json:"access"`
	Limits rawCollectionLimits `json:"limits,omitempty"`
}

type rawCollectionLimits struct {
	MaxDocuments     *int `json:"maxDocuments,omitempty"`
	MaxDocumentBytes *int `json:"maxDocumentBytes,omitempty"`
}

var allOperations = [...]Operation{
	OperationList,
	OperationRead,
	OperationCreate,
	OperationUpdate,
	OperationDelete,
	OperationSubscribe,
}

func ParseDeclaration(data []byte, limits Limits) (Declaration, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return Declaration{}, fmt.Errorf("%w: host limits are invalid", ErrInvalidDeclaration)
	}
	if len(data) == 0 {
		return EmptyDeclaration(), nil
	}
	if len(data) > MaxDeclarationBytes {
		return Declaration{}, fmt.Errorf("%w: file exceeds %d bytes", ErrInvalidDeclaration, MaxDeclarationBytes)
	}
	if _, err := normalizeJSONObject(data, MaxDeclarationBytes, 32, 256); err != nil {
		return Declaration{}, fmt.Errorf("%w: malformed JSON or duplicate object key", ErrInvalidDeclaration)
	}
	var raw rawDeclaration
	if err := decodeStrict(data, &raw); err != nil {
		return Declaration{}, fmt.Errorf("%w: %v", ErrInvalidDeclaration, err)
	}
	if raw.Version != ProtocolVersion {
		return Declaration{}, fmt.Errorf("%w: version must be %d", ErrInvalidDeclaration, ProtocolVersion)
	}
	if raw.Collections == nil {
		return Declaration{}, fmt.Errorf("%w: collections is required", ErrInvalidDeclaration)
	}
	if len(raw.Collections) > limits.MaxCollections {
		return Declaration{}, fmt.Errorf("%w: at most %d collections may be declared", ErrInvalidDeclaration, limits.MaxCollections)
	}
	declaration := Declaration{Version: raw.Version, Collections: make(map[string]CollectionPolicy, len(raw.Collections))}
	for name, value := range raw.Collections {
		if !ValidCollectionName(name) {
			return Declaration{}, fmt.Errorf("%w: invalid collection name %q", ErrInvalidDeclaration, name)
		}
		access, err := parseCollectionAccess(value.Access)
		if err != nil {
			return Declaration{}, fmt.Errorf("%w: collection %q: %v", ErrInvalidDeclaration, name, err)
		}
		maxDocuments := limits.MaxDocuments
		if value.Limits.MaxDocuments != nil {
			maxDocuments = *value.Limits.MaxDocuments
		}
		maxDocumentBytes := limits.MaxDocumentBytes
		if value.Limits.MaxDocumentBytes != nil {
			maxDocumentBytes = *value.Limits.MaxDocumentBytes
		}
		if maxDocuments < 1 || maxDocuments > limits.MaxDocuments {
			return Declaration{}, fmt.Errorf("%w: collection %q maxDocuments must be between 1 and %d", ErrInvalidDeclaration, name, limits.MaxDocuments)
		}
		if maxDocumentBytes < 2 || maxDocumentBytes > limits.MaxDocumentBytes {
			return Declaration{}, fmt.Errorf("%w: collection %q maxDocumentBytes must be between 2 and %d", ErrInvalidDeclaration, name, limits.MaxDocumentBytes)
		}
		declaration.Collections[name] = CollectionPolicy{
			Access: access, MaxDocuments: maxDocuments, MaxDocumentBytes: maxDocumentBytes,
		}
	}
	return declaration, nil
}

func validateDeclaration(value Declaration, limits Limits) error {
	if value.Version != ProtocolVersion || value.Collections == nil || len(value.Collections) > limits.MaxCollections {
		return errors.New("declaration version or collection count is invalid")
	}
	for name, policy := range value.Collections {
		if !ValidCollectionName(name) || policy.MaxDocuments < 1 || policy.MaxDocuments > limits.MaxDocuments ||
			policy.MaxDocumentBytes < 2 || policy.MaxDocumentBytes > limits.MaxDocumentBytes ||
			len(policy.Access) != len(allOperations) {
			return fmt.Errorf("collection %q has invalid limits or access", name)
		}
		for _, operation := range allOperations {
			access, ok := policy.Access[operation]
			if !ok || access != AccessAnyone && access != AccessAuthenticated && access != AccessNobody {
				return fmt.Errorf("collection %q has invalid access for %s", name, operation)
			}
		}
	}
	return nil
}

func parseCollectionAccess(raw json.RawMessage) (map[Operation]Access, error) {
	if len(raw) == 0 {
		return nil, errors.New("access is required")
	}
	var profile string
	if err := json.Unmarshal(raw, &profile); err == nil {
		if profile != "shared" {
			return nil, fmt.Errorf("unknown access profile %q", profile)
		}
		access := make(map[Operation]Access, len(allOperations))
		for _, operation := range allOperations {
			access[operation] = AccessAnyone
		}
		return access, nil
	}
	var values map[string]Access
	if err := decodeStrict(raw, &values); err != nil {
		return nil, errors.New("access must be \"shared\" or an operation object")
	}
	if len(values) != len(allOperations) {
		return nil, errors.New("expanded access must state every operation exactly once")
	}
	access := make(map[Operation]Access, len(values))
	for key, value := range values {
		operation := Operation(key)
		if !validOperation(operation) {
			return nil, fmt.Errorf("unknown access operation %q", key)
		}
		if value != AccessAnyone && value != AccessAuthenticated && value != AccessNobody {
			return nil, fmt.Errorf("invalid access value %q for %s", value, operation)
		}
		access[operation] = value
	}
	return access, nil
}

func validOperation(value Operation) bool {
	for _, operation := range allOperations {
		if value == operation {
			return true
		}
	}
	return false
}

func ValidCollectionName(value string) bool {
	if len(value) < 1 || len(value) > 48 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range []byte(value[1:]) {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func ValidDocumentID(value string) bool {
	if len(value) < 1 || len(value) > 64 || value == "." || value == ".." {
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
