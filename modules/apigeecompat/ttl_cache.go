package apigeecompat

import (
	"sync"
	"time"
)

// ttlCache is a generic in-memory cache with per-entry TTL.
// Safe for concurrent use.
//
// Nil values (*V == nil) are valid cache entries and are used as negative-lookup
// sentinels (e.g. to cache a Firestore NotFound result so repeated misses do not
// hit the remote store).
//
// Expired entries are evicted lazily on Get.
type ttlCache[V any] struct {
	mu      sync.RWMutex
	entries map[string]ttlEntry[V]
	ttl     time.Duration
}

type ttlEntry[V any] struct {
	value   *V
	expires time.Time
	set     bool // distinguishes "entry present with nil value" from "no entry"
}

func newTTLCache[V any](ttl time.Duration) *ttlCache[V] {
	return &ttlCache[V]{
		entries: make(map[string]ttlEntry[V]),
		ttl:     ttl,
	}
}

// Get returns the cached value and true if the key is present and not expired.
// The value may be nil (negative-lookup sentinel). Expired entries are evicted
// lazily — the map entry is deleted before returning false.
func (c *ttlCache[V]) Get(key string) (*V, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || !e.set {
		return nil, false
	}
	if time.Now().After(e.expires) {
		// Lazy eviction: remove the stale entry.
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}
	return e.value, true
}

// Set stores a value with the cache's TTL. v may be nil to cache a negative lookup.
func (c *ttlCache[V]) Set(key string, v *V) {
	c.mu.Lock()
	c.entries[key] = ttlEntry[V]{value: v, expires: time.Now().Add(c.ttl), set: true}
	c.mu.Unlock()
}

// Delete removes a key from the cache.
func (c *ttlCache[V]) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}
