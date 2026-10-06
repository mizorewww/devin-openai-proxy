package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SignedThinking is one upstream-issued reasoning block: the thinking text plus
// the opaque signature the server uses to verify/continue the trace on the next
// turn (ChatMessage #11/#12/#13/#18). The proxy never decrypts it — it just
// round-trips the blob so multi-turn requests keep a verified CoT.
type SignedThinking struct {
	Text       string
	Signature  string
	SigType    string // "sealed" / "non-sealed" / ...
	Redacted   bool
	Selector   string // upstream model selector that issued it
	StoredAt   time.Time
}

// sigStore rehydrates signatures on rebuilt history. The client only has to
// echo either the assistant TEXT or the reasoning_content verbatim — the blob
// is indexed under both digests. A forked/edited turn simply misses and rides
// unsigned, which the swe family tolerates.
type sigStore struct {
	mu   sync.Mutex
	m    map[string]*SignedThinking
	keys []string // FIFO eviction
	max  int
	ttl  time.Duration
}

func newSigStore(max int, ttl time.Duration) *sigStore {
	return &sigStore{m: make(map[string]*SignedThinking), max: max, ttl: ttl}
}

func (s *sigStore) put(key string, t *SignedThinking) {
	if key == "" || t == nil || t.Signature == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; !ok {
		s.keys = append(s.keys, key)
		for len(s.keys) > s.max {
			delete(s.m, s.keys[0])
			s.keys = s.keys[1:]
		}
	}
	s.m[key] = t
}

func (s *sigStore) get(key, selector string) *SignedThinking {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.m[key]
	if t == nil {
		return nil
	}
	if s.ttl > 0 && time.Since(t.StoredAt) > s.ttl {
		return nil
	}
	// Audit rule (pi-devin): only replay a signature to the same upstream
	// selector that issued it — cross-model replay is refused.
	if selector != "" && t.Selector != "" && t.Selector != selector {
		return nil
	}
	return t
}

func digestOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d\x00%s\x00", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))
}
