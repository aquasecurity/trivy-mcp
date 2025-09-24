package findings

type ListFilters struct {
	MinSeverity Severity   `json:"min_severity,omitempty"`
	Categories  []Category `json:"categories,omitempty"` // if empty = all
	Limit       int        `json:"limit"`
	PageToken   string     `json:"page_token,omitempty"`
}

type ListResult struct {
	Findings       []Finding         `json:"findings"`
	PolicyFailures []PolicyFailure   `json:"policy_failures,omitempty"` // Aqua Platform only
	NextToken      string            `json:"next_token,omitempty"`
	Meta           map[string]string `json:"meta,omitempty"`
}

type GetRequest struct {
	ID string `json:"id"`
}

type GetResponse struct {
	Finding Finding `json:"finding"`
}

type ScanResponse struct {
	BatchID     string            `json:"batch_id"`
	Fingerprint string            `json:"fingerprint"` // hash of normalized content
	Counts      map[string]int    `json:"counts"`      // by severity/category for quick glance
	Meta        map[string]string `json:"meta,omitempty"`
}
