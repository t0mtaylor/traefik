package wafqueue

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// Store is the minimal valkey surface the hot path and refresher need. It is an interface so
// tests can substitute a fake and so a nil Store degrades to pure fail-open.
type Store interface {
	// Enqueue XADDs a compact job onto streamKey, approx-bounded by maxLen.
	Enqueue(ctx context.Context, streamKey string, maxLen int64, fields map[string]any) error
	// Members returns the union of all set members across keys (SMEMBERS). Missing keys are
	// treated as empty, not an error.
	Members(ctx context.Context, keys []string) ([]string, error)
	// QueueDepth returns the approximate stream length (XLEN).
	QueueDepth(ctx context.Context, streamKey string) (int64, error)
	// Close releases the client.
	Close() error
}

// ValkeyStore is a go-redis-backed Store. It works against a single node or a sentinel-managed
// master via redis.UniversalClient.
type ValkeyStore struct {
	c redis.UniversalClient
}

// NewValkeyStore builds a ValkeyStore. When sentinels are provided it uses a failover client
// keyed on master; otherwise a plain client on addr.
func NewValkeyStore(addr string, sentinels []string, master, password string, db int) *ValkeyStore {
	opts := &redis.UniversalOptions{
		Password: password,
		DB:       db,
	}
	if len(sentinels) > 0 {
		opts.Addrs = sentinels
		opts.MasterName = master
	} else {
		opts.Addrs = []string{addr}
	}
	return &ValkeyStore{c: redis.NewUniversalClient(opts)}
}

// Enqueue implements Store.
func (s *ValkeyStore) Enqueue(ctx context.Context, streamKey string, maxLen int64, fields map[string]any) error {
	return s.c.XAdd(ctx, &redis.XAddArgs{
		Stream: streamKey,
		MaxLen: maxLen,
		Approx: true,
		Values: fields,
	}).Err()
}

// Members implements Store.
func (s *ValkeyStore) Members(ctx context.Context, keys []string) ([]string, error) {
	var out []string
	for _, k := range keys {
		vals, err := s.c.SMembers(ctx, k).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return out, err
		}
		out = append(out, vals...)
	}
	return out, nil
}

// QueueDepth implements Store.
func (s *ValkeyStore) QueueDepth(ctx context.Context, streamKey string) (int64, error) {
	return s.c.XLen(ctx, streamKey).Result()
}

// Close implements Store.
func (s *ValkeyStore) Close() error { return s.c.Close() }
