package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type InMemoryCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		cache: make(map[string]string),
	}
}

func (c *InMemoryCache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = value
	return nil
}

func (c *InMemoryCache) Get(ctx context.Context, key string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.cache[key]
	if !ok {
		return "", fmt.Errorf("key not found")
	}
	return value, nil
}

func (c *InMemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
	return nil
}
