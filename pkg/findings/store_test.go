package findings

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStore_LRUBehavior(t *testing.T) {
	// Create a small store to test LRU eviction
	store := NewStoreWithSize(2)

	// Add first batch
	findings1 := []Finding{
		{ID: "f1", Category: CatVuln, Severity: High},
	}
	store.PutBatch("batch1", findings1)

	// Add second batch
	findings2 := []Finding{
		{ID: "f2", Category: CatVuln, Severity: Medium},
	}
	store.PutBatch("batch2", findings2)

	// Both batches should be present
	len, capacity := store.CacheStats()
	assert.Equal(t, 2, len)
	assert.Equal(t, 2, capacity)

	// Verify we can retrieve from both batches
	f1, ok := store.GetFinding("batch1", "f1")
	assert.True(t, ok)
	assert.Equal(t, "f1", f1.ID)

	f2, ok := store.GetFinding("batch2", "f2")
	assert.True(t, ok)
	assert.Equal(t, "f2", f2.ID)

	// Add third batch - should evict the least recently used (batch1)
	findings3 := []Finding{
		{ID: "f3", Category: CatVuln, Severity: Low},
	}
	store.PutBatch("batch3", findings3)

	// Still only 2 items in cache
	len, _ = store.CacheStats()
	assert.Equal(t, 2, len)

	// batch1 should be evicted (not accessible)
	_, ok = store.GetFinding("batch1", "f1")
	assert.False(t, ok)

	// batch2 and batch3 should still be accessible
	_, ok = store.GetFinding("batch2", "f2")
	assert.True(t, ok)

	_, ok = store.GetFinding("batch3", "f3")
	assert.True(t, ok)
}

func TestStore_ListWithLRU(t *testing.T) {
	store := NewStoreWithSize(5)

	findings := []Finding{
		{ID: "f1", Category: CatVuln, Severity: High},
		{ID: "f2", Category: CatMisconfig, Severity: Medium},
	}
	store.PutBatch("test-batch", findings)

	// Test listing
	result, err := store.List("test-batch", Low, nil, 10, "")
	assert.NoError(t, err)
	assert.Len(t, result.Findings, 2)

	// Test with non-existent batch
	_, err = store.List("missing-batch", Low, nil, 10, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown batch missing-batch")
}

func TestStore_PutBatchWithPolicies(t *testing.T) {
	store := NewStoreWithSize(5)

	findings := []Finding{
		{ID: "f1", Category: CatVuln, Severity: High},
		{ID: "f2", Category: CatMisconfig, Severity: Medium},
	}

	policies := []PolicyFailure{
		{
			ID:         "p1",
			PolicyID:   "policy-uuid-1",
			PolicyName: "Security Policy",
			Reason:     "Unauthorized access",
			Enforced:   true,
		},
		{
			ID:         "p2",
			PolicyID:   "policy-uuid-2",
			PolicyName: "Compliance Policy",
			Reason:     "Non-compliant configuration",
			Enforced:   false,
		},
	}

	store.PutBatchWithPolicies("test-batch", findings, policies)

	// Test listing includes both findings and policies
	result, err := store.List("test-batch", Low, nil, 10, "")
	assert.NoError(t, err)
	assert.Len(t, result.Findings, 2)
	assert.Len(t, result.PolicyFailures, 2)
}

func TestStore_GetFinding_EdgeCases(t *testing.T) {
	store := NewStoreWithSize(5)

	findings := []Finding{
		{ID: "f1", Category: CatVuln, Severity: High},
	}
	store.PutBatch("test-batch", findings)

	tests := []struct {
		name        string
		batchID     string
		findingID   string
		expectFound bool
	}{
		{"existing finding", "test-batch", "f1", true},
		{"non-existent finding", "test-batch", "f2", false},
		{"non-existent batch", "missing-batch", "f1", false},
		{"empty batch ID", "", "f1", false},
		{"empty finding ID", "test-batch", "", false},
		{"both empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding, found := store.GetFinding(tt.batchID, tt.findingID)
			if tt.expectFound {
				assert.True(t, found)
				assert.Equal(t, tt.findingID, finding.ID)
			} else {
				assert.False(t, found)
				assert.Equal(t, Finding{}, finding) // Should return zero value
			}
		})
	}
}

func TestStore_List_Filtering(t *testing.T) {
	store := NewStoreWithSize(10)

	findings := []Finding{
		{ID: "critical1", Category: CatVuln, Severity: Critical},
		{ID: "high1", Category: CatVuln, Severity: High},
		{ID: "medium1", Category: CatMisconfig, Severity: Medium},
		{ID: "low1", Category: CatLicense, Severity: Low},
		{ID: "unknown1", Category: CatSecret, Severity: Unknown},
	}
	store.PutBatch("test-batch", findings)

	tests := []struct {
		name        string
		minSeverity Severity
		categories  []Category
		expectedIDs []string
	}{
		{
			name:        "critical only",
			minSeverity: Critical,
			categories:  nil,
			expectedIDs: []string{"critical1"},
		},
		{
			name:        "high and above",
			minSeverity: High,
			categories:  nil,
			expectedIDs: []string{"critical1", "high1"},
		},
		{
			name:        "medium and above",
			minSeverity: Medium,
			categories:  nil,
			expectedIDs: []string{"critical1", "high1", "medium1"},
		},
		{
			name:        "all severities",
			minSeverity: Unknown,
			categories:  nil,
			expectedIDs: []string{"critical1", "high1", "medium1", "low1", "unknown1"},
		},
		{
			name:        "vuln category only",
			minSeverity: Unknown,
			categories:  []Category{CatVuln},
			expectedIDs: []string{"critical1", "high1"},
		},
		{
			name:        "multiple categories",
			minSeverity: Unknown,
			categories:  []Category{CatVuln, CatMisconfig},
			expectedIDs: []string{"critical1", "high1", "medium1"},
		},
		{
			name:        "high severity vuln category",
			minSeverity: High,
			categories:  []Category{CatVuln},
			expectedIDs: []string{"critical1", "high1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := store.List("test-batch", tt.minSeverity, tt.categories, 10, "")
			assert.NoError(t, err)

			// Extract IDs from result
			actualIDs := make([]string, len(result.Findings))
			for i, finding := range result.Findings {
				actualIDs[i] = finding.ID
			}

			assert.ElementsMatch(t, tt.expectedIDs, actualIDs)
		})
	}
}

func TestStore_List_Pagination(t *testing.T) {
	store := NewStoreWithSize(10)

	// Create many findings
	var findings []Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, Finding{
			ID:       fmt.Sprintf("f%d", i),
			Category: CatVuln,
			Severity: High,
		})
	}
	store.PutBatch("test-batch", findings)

	// Test pagination
	tests := []struct {
		name        string
		limit       float64
		token       string
		expectMore  bool
		expectCount int
	}{
		{"first page", 5, "", true, 5},
		{"second page", 5, "", false, 5},   // This would need proper cursor implementation
		{"large limit", 25, "", false, 20}, // Should return all findings
		{"zero limit", 0, "", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := store.List("test-batch", Low, nil, tt.limit, tt.token)
			assert.NoError(t, err)

			if tt.limit > 0 {
				assert.LessOrEqual(t, len(result.Findings), int(tt.limit))
			}

			if tt.expectCount > 0 {
				assert.Equal(t, tt.expectCount, len(result.Findings))
			}
		})
	}
}

func TestStore_NewStore(t *testing.T) {
	// Test default constructor
	store := NewStore()
	assert.NotNil(t, store)

	len, capacity := store.CacheStats()
	assert.Equal(t, 0, len)
	assert.Greater(t, capacity, 0) // Should have some default capacity

	// Test with custom size
	store2 := NewStoreWithSize(100)
	assert.NotNil(t, store2)

	len2, capacity2 := store2.CacheStats()
	assert.Equal(t, 0, len2)
	assert.Equal(t, 100, capacity2)
}

func TestStore_CursorEncodingDecoding(t *testing.T) {
	tests := []struct {
		name    string
		cursor  pageCursor
		wantErr bool
	}{
		{
			name: "complete cursor",
			cursor: pageCursor{
				AfterID:    "test-id",
				MinSev:     High,
				Categories: []Category{CatVuln, CatMisconfig},
				BatchID:    "test-batch",
			},
			wantErr: false,
		},
		{
			name: "minimal cursor",
			cursor: pageCursor{
				MinSev:  Low,
				BatchID: "batch",
			},
			wantErr: false,
		},
		{
			name:    "empty cursor",
			cursor:  pageCursor{},
			wantErr: false,
		},
		{
			name: "cursor with special characters",
			cursor: pageCursor{
				AfterID:    "test-id!@#$%",
				MinSev:     Critical,
				Categories: []Category{CatSecret},
				BatchID:    "batch with spaces & symbols!",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test encoding
			encoded := encodeCursor(tt.cursor)
			assert.NotEmpty(t, encoded)

			// Test decoding
			decoded, err := decodeCursor(encoded)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.cursor, decoded)
		})
	}
}

func TestStore_CursorDecoding_InvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"invalid base64", "not-base64!", true},
		{"valid base64 invalid json", "bm90LWpzb24", true}, // "not-json" in base64
		{"empty string", "", true},
		{"random string", "random", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeCursor(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
