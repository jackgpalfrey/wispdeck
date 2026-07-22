package wispist

import (
	"sync"
)

type hubEvent struct {
	Change      Change
	ResetReason string
}

type subscription struct {
	id          uint64
	collections map[string]struct{}
	events      chan hubEvent
}

type changeHub struct {
	mu          sync.Mutex
	nextID      uint64
	byNamespace map[string]map[uint64]*subscription
	queueSize   int
}

func newChangeHub(queueSize int) *changeHub {
	return &changeHub{byNamespace: make(map[string]map[uint64]*subscription), queueSize: queueSize}
}

func (h *changeHub) subscribe(namespace string, collections []string) (<-chan hubEvent, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	value := &subscription{
		id: h.nextID, collections: make(map[string]struct{}, len(collections)),
		events: make(chan hubEvent, h.queueSize),
	}
	for _, collection := range collections {
		value.collections[collection] = struct{}{}
	}
	if h.byNamespace[namespace] == nil {
		h.byNamespace[namespace] = make(map[uint64]*subscription)
	}
	h.byNamespace[namespace][value.id] = value
	var once sync.Once
	return value.events, func() {
		once.Do(func() { h.unsubscribe(namespace, value.id) })
	}
}

func (h *changeHub) unsubscribe(namespace string, id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	values := h.byNamespace[namespace]
	value, ok := values[id]
	if !ok {
		return
	}
	delete(values, id)
	close(value.events)
	if len(values) == 0 {
		delete(h.byNamespace, namespace)
	}
}

func (h *changeHub) publish(namespace string, change Change) {
	h.mu.Lock()
	defer h.mu.Unlock()
	values := h.byNamespace[namespace]
	for id, value := range values {
		if _, wanted := value.collections[change.Collection]; !wanted {
			continue
		}
		select {
		case value.events <- hubEvent{Change: change}:
		default:
			delete(values, id)
			close(value.events)
		}
	}
	if len(values) == 0 {
		delete(h.byNamespace, namespace)
	}
}

func (h *changeHub) reset(namespace, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	values := h.byNamespace[namespace]
	for id, value := range values {
		// A purge invalidates every queued change. Drain the bounded queue and
		// deliver one explicit reset before closing the subscription.
		for len(value.events) > 0 {
			<-value.events
		}
		value.events <- hubEvent{ResetReason: reason}
		close(value.events)
		delete(values, id)
	}
	delete(h.byNamespace, namespace)
}
