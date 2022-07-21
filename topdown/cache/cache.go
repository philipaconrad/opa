// Copyright 2020 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package cache defines the inter-query cache interface that can cache data across queries
package cache

import (
	"container/list"

	"github.com/open-policy-agent/opa/ast"

	"sync"

	"github.com/open-policy-agent/opa/util"
)

const (
	defaultMaxSizeBytes = int64(0) // unlimited
)

// Config represents the configuration of the inter-query cache.
type Config struct {
	InterQueryBuiltinCache InterQueryBuiltinCacheConfig `json:"inter_query_builtin_cache"`
}

// InterQueryBuiltinCacheConfig represents the configuration of the inter-query cache that built-in functions can utilize.
type InterQueryBuiltinCacheConfig struct {
	MaxSizeBytes *int64 `json:"max_size_bytes,omitempty"`
}

// ParseCachingConfig returns the config for the inter-query cache.
func ParseCachingConfig(raw []byte) (*Config, error) {
	if raw == nil {
		maxSize := new(int64)
		*maxSize = defaultMaxSizeBytes
		return &Config{InterQueryBuiltinCache: InterQueryBuiltinCacheConfig{MaxSizeBytes: maxSize}}, nil
	}

	var config Config

	if err := util.Unmarshal(raw, &config); err == nil {
		if err = config.validateAndInjectDefaults(); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	return &config, nil
}

func (c *Config) validateAndInjectDefaults() error {
	if c.InterQueryBuiltinCache.MaxSizeBytes == nil {
		maxSize := new(int64)
		*maxSize = defaultMaxSizeBytes
		c.InterQueryBuiltinCache.MaxSizeBytes = maxSize
	}
	return nil
}

// InterQueryCacheValue defines the interface for the data that the inter-query cache holds.
type InterQueryCacheValue interface {
	SizeInBytes() int64
}

// InterQueryCache defines the interface for the inter-query cache.
type InterQueryCache interface {
	Get(key ast.Value) (value InterQueryCacheValue, found bool)
	Insert(key ast.Value, value InterQueryCacheValue) int
	Delete(key ast.Value)
	UpdateConfig(config *Config)
}

// NewInterQueryCache returns a new inter-query cache.
func NewInterQueryCache(config *Config) InterQueryCache {
	return &cache{
		items:  map[string]InterQueryCacheValue{},
		usage:  0,
		config: config,
		l:      list.New(),
	}
}

type cache struct {
	items  map[string]InterQueryCacheValue
	usage  int64
	config *Config
	l      *list.List
	mtx    sync.Mutex
}

// Insert inserts a key k into the cache with value v.
func (c *cache) Insert(k ast.Value, v InterQueryCacheValue) (dropped int) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.unsafeInsert(k, v)
}

// Get returns the value in the cache for k.
func (c *cache) Get(k ast.Value) (InterQueryCacheValue, bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.unsafeGet(k)
}

// Delete deletes the value in the cache for k.
func (c *cache) Delete(k ast.Value) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.unsafeDelete(k)
}

func (c *cache) UpdateConfig(config *Config) {
	if config == nil {
		return
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.config = config
}

func (c *cache) unsafeInsert(k ast.Value, v InterQueryCacheValue) (dropped int) {
	size := v.SizeInBytes()
	limit := c.maxSizeBytes()

	if limit > 0 {
		if size > limit {
			dropped++
			return dropped
		}

		for key := c.l.Front(); key != nil && (c.usage+size > limit); key = key.Next() {
			dropKey := key.Value.(ast.Value)
			c.unsafeDelete(dropKey)
			c.l.Remove(key)
			dropped++
		}
	}

	c.items[k.String()] = v
	c.l.PushBack(k)
	c.usage += size
	return dropped
}

func (c *cache) unsafeGet(k ast.Value) (InterQueryCacheValue, bool) {
	value, ok := c.items[k.String()]
	return value, ok
}

func (c *cache) unsafeDelete(k ast.Value) {
	value, ok := c.unsafeGet(k)
	if !ok {
		return
	}

	c.usage -= int64(value.SizeInBytes())
	delete(c.items, k.String())
}

func (c *cache) maxSizeBytes() int64 {
	if c.config == nil {
		return defaultMaxSizeBytes
	}
	return *c.config.InterQueryBuiltinCache.MaxSizeBytes
}

// Note(philipc): The non-deterministic builtins cache exists to allow
// decision logging to preserve the results of different non-deterministic
// builtin function calls. This paves the way for later reconstruction and
// replay of policies from their decision logs.
// There are constraints however, namely that we only save the first
// result we see for a given set of input parameters. This means that for
// builtins like http.send, we assume that the outside world is able to
// return arbitrary content, but that the result will be idempotent across
// successive calls of that builtin with the same inputs. Otherwise, we
// begin to descend into selective tracing of just the non-deterministic
// builtins.
type NDConfig interface {
}

// NDBuiltinResultCache defines the interface for the specialized cache.
type NDBuiltinResultCache interface {
	Get(builtinName string, k *ast.Term) (value *ast.Term, found bool)
	Insert(builtinName string, k *ast.Term, value *ast.Term)
	Delete(builtinName string, k *ast.Term)
	//UpdateConfig(config *NDConfig)
}

// Two-level map:
// - First layer: builtin name
//   - Second layer: inputs -> outputs
// Note(philipc): This is mostly a ripoff of the inter-query cache.
// We suffer here because we stringify the keys to simplify insertion.
type ndBuiltinResultCache struct {
	items  map[string]map[string]*ast.Term
	config *NDConfig
	mtx    sync.Mutex
}

// NewInterQueryCache returns a new inter-query cache.
func NewNDBuiltinResultCache(config *NDConfig) NDBuiltinResultCache {
	return &ndBuiltinResultCache{
		items:  map[string]map[string]*ast.Term{},
		config: config,
	}
}

// Insert inserts a key k into the cache with value v.
func (c *ndBuiltinResultCache) Insert(builtinName string, k *ast.Term, v *ast.Term) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	entries, exists := c.items[builtinName]
	if !exists {
		c.items[builtinName] = make(map[string]*ast.Term)
	}
	entries[k.String()] = v // k will be an array term.
}

// Get returns the value in the cache for k.
func (c *ndBuiltinResultCache) Get(builtinName string, k *ast.Term) (*ast.Term, bool) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	// If the second-level map doesn't exist, exit early.
	if _, exists := c.items[builtinName]; !exists {
		return nil, false
	}
	// If the entry doesn't exist, exit early. Otherwise return the value.
	entry, exists := c.items[builtinName][k.String()]
	if !exists {
		return nil, false
	}
	return entry, true
}

func (c *ndBuiltinResultCache) Delete(builtinName string, k *ast.Term) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	// Delete the value if its second-level map exists.
	if _, exists := c.items[builtinName]; exists {
		delete(c.items[builtinName], k.String())
	}
}

// func (c *ndBuiltinResultCache) UpdateConfig(config *NDConfig) {
// 	if config == nil {
// 		return
// 	}
// 	c.mtx.Lock()
// 	defer c.mtx.Unlock()
// 	c.config = config
// }
