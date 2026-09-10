// Package cache provides a simple, concurrent-safe in-memory cache with expiration support.
package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// Cache stores arbitrary data with expiration time.
type Cache struct {
	items                        sync.Map
	counter                      atomic.Uint32
	defaultDuration              time.Duration
	defaultExpirationCheckPeriod uint32
}

const defaultExpirationPeriod = 100

// An item represents arbitrary data with expiration time.
type item struct {
	// The data stored in the cache
	data any
	// The expiration time in nanoseconds since the Unix epoch
	expires int64
}

// New creates a new cache that asynchronously cleans
// expired entries after the given time passes.
func New(defaultDuration time.Duration) *Cache {

	if defaultDuration <= 0 {
		defaultDuration = 10 * time.Minute
	}

	cache := &Cache{
		defaultDuration:              defaultDuration,
		defaultExpirationCheckPeriod: defaultExpirationPeriod,
	}

	return cache
}

// Set sets a value for the given key with an expiration duration.
// If the duration is less than 0, it will be stored forever.
// If the duration is 0, the default expiration time will be used
func (cache *Cache) Set(key string, value any, duration time.Duration) {

	// A zero value means no expiration
	var expires int64

	if duration == 0 {
		duration = cache.defaultDuration
	}

	if duration > 0 {
		expires = time.Now().Add(duration).UnixNano()
	}

	cache.items.Store(key, item{
		data:    value,
		expires: expires,
	})

	// Delete expired entries periodically.
	// The following instructions are not synchronized, but we do not care as long as DeleteExpired() is called
	// "approximately" every 100 writes.
	count := cache.counter.Add(1)
	if count >= cache.defaultExpirationCheckPeriod {
		cache.DeleteExpired()
		cache.counter.Store(0)
	}
}

// Get gets the value for the given key.
func (cache *Cache) Get(key string) (any, bool) {
	obj, exists := cache.items.Load(key)

	if !exists {
		return nil, false
	}

	item := obj.(item)

	if item.expires > 0 && time.Now().UnixNano() > item.expires {
		// Use the fact that the caller is going to get an expiration error to check for entries which have expired.
		// This opportunistic expiration strategy impacts latency of the error case but seems an acceptable compromise.
		cache.DeleteExpired()
		return nil, false
	}

	return item.data, true
}

func (cache *Cache) DeleteExpired() {
	now := time.Now().UnixNano()

	fn := func(key, value any) bool {
		item := value.(item)

		if item.expires > 0 && now > item.expires {
			cache.items.Delete(key)
		}

		return true
	}

	cache.items.Range(fn)

}

// Delete deletes the key and its value from the cache.
func (cache *Cache) Delete(key string) {
	cache.items.Delete(key)
}
