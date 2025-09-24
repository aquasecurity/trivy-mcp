package findings

import "strings"

type Severity uint8

const (
	Unknown Severity = iota
	Low
	Medium
	High
	Critical
)

func ParseSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	default:
		return Unknown
	}
}
