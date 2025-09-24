package findings

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

type batch struct {
	Findings       []Finding
	PolicyFailures []PolicyFailure
	Index          map[string]int
	PolicyIndex    map[string]int
}

const DefaultCacheSize = 10
const MaxResultSize = 200
const DefaultLimit = 50

type Store struct {
	mu       sync.RWMutex
	data     *lru.Cache[string, *batch]
	capacity int
}

func NewStore() *Store {
	return NewStoreWithSize(DefaultCacheSize)
}

func NewStoreWithSize(size int) *Store {
	cache, _ := lru.New[string, *batch](size)
	return &Store{data: cache, capacity: size}
}

func (s *Store) PutBatch(batchID string, fs []Finding) {
	s.PutBatchWithPolicies(batchID, fs, []PolicyFailure{})
}

func (s *Store) PutBatchWithPolicies(batchID string, fs []Finding, pf []PolicyFailure) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := make(map[string]int, len(fs))
	for i, f := range fs {
		idx[f.ID] = i
	}
	policyIdx := make(map[string]int, len(pf))
	for i, p := range pf {
		policyIdx[p.ID] = i
	}
	s.data.Add(batchID, &batch{
		Findings:       fs,
		PolicyFailures: pf,
		Index:          idx,
		PolicyIndex:    policyIdx,
	})
}

func (s *Store) GetFinding(batchID, id string) (Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.data.Get(batchID)
	if !ok {
		return Finding{}, false
	}
	i, ok := b.Index[id]
	if !ok {
		return Finding{}, false
	}
	return b.Findings[i], true
}

type pageCursor struct {
	AfterID    string     `json:"after_id,omitempty"`
	MinSev     Severity   `json:"min_sev"`
	Categories []Category `json:"cats,omitempty"`
	BatchID    string     `json:"batch_id"`
}

func encodeCursor(pc pageCursor) string {
	b, _ := json.Marshal(pc)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(tok string) (pageCursor, error) {
	var pc pageCursor
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return pc, err
	}
	err = json.Unmarshal(b, &pc)
	return pc, err
}

// Keyset pagination: we pre-sort by (Severity desc, ID asc)
func (s *Store) List(batchID string, min Severity, cats []Category, limit float64, token string) (ListResult, error) {
	if limit <= 0 || limit > MaxResultSize {
		limit = DefaultLimit
	}
	pc := pageCursor{BatchID: batchID, MinSev: min, Categories: cats}
	afterID := ""
	if token != "" {
		var err error
		pc, err = decodeCursor(token)
		if err != nil {
			return ListResult{}, err
		}
		afterID = pc.AfterID
	}

	s.mu.RLock()
	b, ok := s.data.Get(batchID)
	s.mu.RUnlock()
	if !ok {
		return ListResult{}, fmt.Errorf("unknown batch %s, run a scan first", batchID)
	}

	matchesCat := func(c Category) bool {
		if len(cats) == 0 {
			return true
		}
		for _, x := range cats {
			if x == c {
				return true
			}
		}
		return false
	}

	out := make([]Finding, 0, int(limit))
	started := (afterID == "")
	for _, f := range b.Findings { // already sorted
		if !started {
			if f.ID == afterID {
				started = true
			}
			continue
		}
		if f.Severity < min || !matchesCat(f.Category) {
			continue
		}
		out = append(out, f)
		if len(out) == int(limit) {
			pc.AfterID = f.ID
			return ListResult{Findings: out, PolicyFailures: b.PolicyFailures, NextToken: encodeCursor(pc)}, nil
		}
	}
	return ListResult{Findings: out, PolicyFailures: b.PolicyFailures}, nil
}

// CacheStats returns information about the cache state
func (s *Store) CacheStats() (len int, capacity int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Len(), s.capacity
}
