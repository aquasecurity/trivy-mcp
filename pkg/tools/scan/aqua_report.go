package scan

import "time"

type AssuranceReport struct {
	Results []Results `json:"Results"`
}
type Rootfs struct {
	Type    string `json:"type"`
	DiffIds any    `json:"diff_ids"`
}
type Config struct {
}
type ImageConfig struct {
	Architecture string    `json:"architecture"`
	Created      time.Time `json:"created"`
	Os           string    `json:"os"`
	Rootfs       Rootfs    `json:"rootfs"`
	Config       Config    `json:"config"`
}
type Metadata struct {
	ImageConfig ImageConfig `json:"ImageConfig"`
}
type Identifier struct {
	Purl string `json:"PURL"`
	UID  string `json:"UID"`
}
type Layer struct {
}
type Locations struct {
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}
type Packages struct {
	ID         string      `json:"ID"`
	Name       string      `json:"Name"`
	Identifier Identifier  `json:"Identifier"`
	Version    string      `json:"Version"`
	Licenses   []string    `json:"Licenses"`
	Indirect   bool        `json:"Indirect,omitempty"`
	DependsOn  []string    `json:"DependsOn,omitempty"`
	Layer      Layer       `json:"Layer"`
	Locations  []Locations `json:"Locations"`
}
type PkgIdentifier struct {
	Purl string `json:"PURL"`
	UID  string `json:"UID"`
}
type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
}
type Epss struct {
	Date       string  `json:"Date"`
	Percentile float64 `json:"Percentile"`
	Score      float64 `json:"Score"`
}
type Custom struct {
	Epss       Epss     `json:"EPSS"`
	DepPath    string   `json:"depPath"`
	Indirect   bool     `json:"indirect"`
	LineNumber int      `json:"lineNumber"`
	PkgRoots   []string `json:"pkgRoots"`
}
type VendorSeverity struct {
	CblMariner int `json:"cbl-mariner"`
	Ghsa       int `json:"ghsa"`
	Nvd        int `json:"nvd"`
	Redhat     int `json:"redhat"`
}
type Ghsa struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}
type Nvd struct {
	V40Vector string  `json:"V40Vector"`
	V40Score  float64 `json:"V40Score"`
}
type Redhat struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}
type Cvss struct {
	Ghsa   Ghsa   `json:"ghsa"`
	Nvd    Nvd    `json:"nvd"`
	Redhat Redhat `json:"redhat"`
}
type Vulnerabilities struct {
	VulnerabilityID  string         `json:"VulnerabilityID"`
	PkgID            string         `json:"PkgID"`
	PkgName          string         `json:"PkgName"`
	PkgIdentifier    PkgIdentifier  `json:"PkgIdentifier"`
	InstalledVersion string         `json:"InstalledVersion"`
	FixedVersion     string         `json:"FixedVersion"`
	Status           string         `json:"Status"`
	Layer            Layer          `json:"Layer"`
	SeveritySource   string         `json:"SeveritySource"`
	PrimaryURL       string         `json:"PrimaryURL"`
	DataSource       DataSource     `json:"DataSource"`
	Custom           Custom         `json:"Custom"`
	Title            string         `json:"Title"`
	Description      string         `json:"Description"`
	Severity         string         `json:"Severity"`
	CweIDs           []string       `json:"CweIDs"`
	VendorSeverity   VendorSeverity `json:"VendorSeverity"`
	Cvss             Cvss           `json:"CVSS"`
	References       []string       `json:"References"`
	PublishedDate    time.Time      `json:"PublishedDate"`
	LastModifiedDate time.Time      `json:"LastModifiedDate"`
}
type MisconfSummary struct {
	Successes int `json:"Successes"`
	Failures  int `json:"Failures"`
}
type Code struct {
	Lines any `json:"Lines"`
}
type RenderedCause struct {
}
type CauseMetadata struct {
	Provider      string        `json:"Provider"`
	Service       string        `json:"Service"`
	Code          Code          `json:"Code"`
	RenderedCause RenderedCause `json:"RenderedCause"`
}
type Misconfigurations struct {
	Type          string        `json:"Type"`
	ID            string        `json:"ID"`
	Avdid         string        `json:"AVDID"`
	Title         string        `json:"Title"`
	Description   string        `json:"Description"`
	Message       string        `json:"Message"`
	Namespace     string        `json:"Namespace"`
	Resolution    string        `json:"Resolution"`
	Severity      string        `json:"Severity"`
	PrimaryURL    string        `json:"PrimaryURL"`
	References    []string      `json:"References"`
	Status        string        `json:"Status"`
	Layer         Layer         `json:"Layer"`
	CauseMetadata CauseMetadata `json:"CauseMetadata"`
}

type VendorScoring struct {
	VendorName string  `json:"vendorName"`
	V3Score    float64 `json:"V3Score,omitempty"`
	V3Vector   string  `json:"V3Vector,omitempty"`
	Severity   int     `json:"Severity"`
}
type ExtraData struct {
	References   []string `json:"References"`
	Direct       string   `json:"Direct"`
	PackageRoots []string `json:"PackageRoots"`
	Epss         Epss     `json:"EPSS"`
}
type ControlResult struct {
	Reason      string `json:"reason"`
	Type        string `json:"type"`
	MatchedData string `json:"matched_data"`
	Location    string `json:"location"`
	Name        string `json:"name"`
}
type PolicyResults struct {
	PolicyID      string          `json:"PolicyID"`
	Enforced      bool            `json:"Enforced"`
	Failed        bool            `json:"Failed"`
	Reason        string          `json:"Reason"`
	Controls      []string        `json:"Controls"`
	ControlResult []ControlResult `json:"ControlResult"`
	PolicyName    string          `json:"policy_name"`
}
type Fix struct {
	Resolution string `json:"Resolution"`
}

type Results struct {
	Avdid            string          `json:"AVDID"`
	Message          string          `json:"Message"`
	Type             int             `json:"Type"`
	Severity         int             `json:"Severity"`
	Title            string          `json:"Title"`
	Filename         string          `json:"Filename"`
	StartLine        int             `json:"StartLine,omitempty"`
	EndLine          int             `json:"EndLine,omitempty"`
	PkgName          string          `json:"PkgName,omitempty"`
	InstalledVersion string          `json:"InstalledVersion,omitempty"`
	FixedVersion     string          `json:"FixedVersion,omitempty"`
	DataSource       string          `json:"DataSource,omitempty"`
	VendorScoring    []VendorScoring `json:"VendorScoring,omitempty"`
	PublishedDate    int             `json:"PublishedDate,omitempty"`
	LastModified     int             `json:"LastModified,omitempty"`
	ExtraData        ExtraData       `json:"ExtraData,omitempty"`
	Resource         string          `json:"Resource,omitempty"`
	PolicyResults    []PolicyResults `json:"PolicyResults,omitempty"`
}
