package wafqueue

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// statsTTL bounds how long per-node stat keys survive without a flush, so a node that leaves
// the swarm eventually drops out of the dashboard aggregate instead of lingering forever.
const statsTTL = time.Hour

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
	// FlushStats mirrors the hot-path counters to valkey: each incr entry is applied as INCRBY
	// (cumulative), each set entry as SET (absolute gauge). All keys get a sliding TTL so dead
	// nodes expire. It is called off the request path by the stats flusher and must fail-open.
	FlushStats(ctx context.Context, incr map[string]int64, set map[string]int64) error
	// Close releases the client.
	Close() error
}

// ValkeyStore is a go-redis-backed Store. It works against a single node or a sentinel-managed
// master via redis.UniversalClient.
type ValkeyStore struct {
	c redis.UniversalClient
}

// Fail-fast valkey client timeouts. Every valkey op runs OFF the request hot path (background
// enqueue/refresh/stats workers), but these tiny timeouts plus zero command retries guarantee
// that a down or churning valkey can never make a background worker block for seconds and pile
// up behind the bounded job channel. A dead dial returns in ~DialTimeout, never the go-redis
// default of 5s with 3 backoff retries.
const (
	valkeyDialTimeout  = 50 * time.Millisecond
	valkeyReadTimeout  = 50 * time.Millisecond
	valkeyWriteTimeout = 50 * time.Millisecond
	valkeyPoolTimeout  = 100 * time.Millisecond
)

// NewValkeyStore builds a ValkeyStore. When sentinels are provided it uses a failover client
// keyed on master; otherwise a plain client on addr.
func NewValkeyStore(addr string, sentinels []string, master, password string, db int) *ValkeyStore {
	opts := &redis.UniversalOptions{
		Password: password,
		DB:       db,
		// Fail fast: tiny timeouts, no command retries, and honour context deadlines so a
		// churning valkey never stalls a background worker.
		DialTimeout:           valkeyDialTimeout,
		ReadTimeout:           valkeyReadTimeout,
		WriteTimeout:          valkeyWriteTimeout,
		PoolTimeout:           valkeyPoolTimeout,
		MaxRetries:            -1, // go-redis: -1 disables retries entirely
		ContextTimeoutEnabled: true,
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

// FlushStats implements Store.
func (s *ValkeyStore) FlushStats(ctx context.Context, incr map[string]int64, set map[string]int64) error {
	if len(incr) == 0 && len(set) == 0 {
		return nil
	}
	pipe := s.c.Pipeline()
	for k, d := range incr {
		pipe.IncrBy(ctx, k, d)
		pipe.Expire(ctx, k, statsTTL)
	}
	for k, v := range set {
		pipe.Set(ctx, k, v, statsTTL)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Close implements Store.
func (s *ValkeyStore) Close() error { return s.c.Close() }
