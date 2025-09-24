//nolint:govet // Auto-generated struct with duplicate JSON tags from Aqua Platform API
package types

import "time"

var Type = map[int32]string{
	0:  "Misconfiguration",
	1:  "Misconfiguration",
	2:  "Misconfiguration",
	3:  "Misconfiguration",
	4:  "Misconfiguration",
	5:  "Misconfiguration",
	6:  "Misconfiguration",
	7:  "Vulnerability",
	8:  "Secret",
	9:  "Misconfiguration",
	10: "Pipeline",
	11: "Sast",
	12: "Misconfiguration",
}

//nolint:govet
type AssuranceReport struct {
	Report struct {
		SchemaVersion int       `json:"SchemaVersion,omitempty"`
		CreatedAt     time.Time `json:"CreatedAt,omitempty"`
		ArtifactName  string    `json:"ArtifactName,omitempty"`
		ArtifactType  string    `json:"ArtifactType,omitempty"`
		Metadata      struct {
			ImageConfig struct {
				Architecture string    `json:"architecture,omitempty"`
				Created      time.Time `json:"created,omitempty"`
				Os           string    `json:"os,omitempty"`
				Rootfs       struct {
					Type    string `json:"type,omitempty"`
					DiffIds any    `json:"diff_ids,omitempty"`
				} `json:"rootfs,omitempty"`
				Config struct {
				} `json:"config,omitempty"`
			} `json:"ImageConfig,omitempty"`
		} `json:"Metadata,omitempty"`
		Results []struct {
			Target   string `json:"Target,omitempty"`
			Class    string `json:"Class,omitempty"`
			Type     string `json:"Type,omitempty"`
			Packages []struct {
				ID         string `json:"ID,omitempty"`
				Name       string `json:"Name,omitempty"`
				Identifier struct {
					Purl string `json:"PURL,omitempty"`
					UID  string `json:"UID,omitempty"`
				} `json:"Identifier,omitempty"`
				Version  string   `json:"Version,omitempty"`
				Licenses []string `json:"Licenses,omitempty"`
				Indirect bool     `json:"Indirect,omitempty"`
				Layer    struct {
				} `json:"Layer,omitempty"`
				Locations []struct {
					StartLine int `json:"StartLine,omitempty"`
					EndLine   int `json:"EndLine,omitempty"`
				} `json:"Locations,omitempty"`
				DependsOn []string `json:"DependsOn,omitempty"`
			} `json:"Packages,omitempty"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID,omitempty"`
				PkgID           string `json:"PkgID,omitempty"`
				PkgName         string `json:"PkgName,omitempty"`
				PkgIdentifier   struct {
					Purl string `json:"PURL,omitempty"`
					UID  string `json:"UID,omitempty"`
				} `json:"PkgIdentifier,omitempty"`
				InstalledVersion string `json:"InstalledVersion,omitempty"`
				FixedVersion     string `json:"FixedVersion,omitempty"`
				Status           string `json:"Status,omitempty"`
				Layer            struct {
				} `json:"Layer,omitempty"`
				SeveritySource string `json:"SeveritySource,omitempty"`
				PrimaryURL     string `json:"PrimaryURL,omitempty"`
				DataSource     struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
				} `json:"DataSource,omitempty"`
				Custom struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string   `json:"depPath,omitempty"`
					Indirect   bool     `json:"indirect,omitempty"`
					LineNumber int      `json:"lineNumber,omitempty"`
					PkgRoots   []string `json:"pkgRoots,omitempty"`
				} `json:"Custom,omitempty"`
				Title          string   `json:"Title,omitempty"`
				Description    string   `json:"Description,omitempty"`
				Severity       string   `json:"Severity,omitempty"`
				CweIDs         []string `json:"CweIDs,omitempty"`
				VendorSeverity struct {
					Azure      int `json:"azure,omitempty"`
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
					Redhat struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"redhat,omitempty"`
				} `json:"CVSS,omitempty"`
				References       []string  `json:"References,omitempty"`
				PublishedDate    time.Time `json:"PublishedDate,omitempty"`
				LastModifiedDate time.Time `json:"LastModifiedDate,omitempty"`
				VendorSeverity0  struct {
					Ghsa     int `json:"ghsa,omitempty"`
					Nvd      int `json:"nvd,omitempty"`
					Redhat   int `json:"redhat,omitempty"`
					SuseCvrf int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity1 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity2 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity3 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss0 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V2Vector string  `json:"V2Vector,omitempty"`
						V3Vector string  `json:"V3Vector,omitempty"`
						V2Score  float64 `json:"V2Score,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity4 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss1 struct {
					Nvd struct {
						V40Vector string  `json:"V40Vector,omitempty"`
						V40Score  float64 `json:"V40Score,omitempty"`
					} `json:"nvd,omitempty"`
					Redhat struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"redhat,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity5 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss2 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity6 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
					Ubuntu int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity7 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
					Ubuntu int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity8 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity9 struct {
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss3 struct {
					Nvd struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
					Redhat struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"redhat,omitempty"`
				} `json:"CVSS,omitempty"`
				Custom0 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity10 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom1 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity11 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom2 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity12 struct {
					Azure      int `json:"azure,omitempty"`
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom3 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity13 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss4 struct {
					Nvd struct {
						V40Vector string  `json:"V40Vector,omitempty"`
						V40Score  float64 `json:"V40Score,omitempty"`
					} `json:"nvd,omitempty"`
					Redhat struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"redhat,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity14 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss5 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				DataSource0 struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
					URL  string `json:"URL,omitempty"`
				} `json:"DataSource,omitempty"`
				Custom4 struct {
					DepPath    string   `json:"depPath,omitempty"`
					Indirect   bool     `json:"indirect,omitempty"`
					LineNumber int      `json:"lineNumber,omitempty"`
					PkgRoots   []string `json:"pkgRoots,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity15 struct {
					Ghsa int `json:"ghsa,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss6 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity16 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss7 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V2Vector string  `json:"V2Vector,omitempty"`
						V3Vector string  `json:"V3Vector,omitempty"`
						V2Score  int     `json:"V2Score,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity17 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom5 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity18 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Ubuntu int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss8 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V2Vector string  `json:"V2Vector,omitempty"`
						V3Vector string  `json:"V3Vector,omitempty"`
						V2Score  int     `json:"V2Score,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				Custom6 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity19 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom7 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity20 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom8 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity21 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Ubuntu int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss9 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V2Vector string  `json:"V2Vector,omitempty"`
						V3Vector string  `json:"V3Vector,omitempty"`
						V2Score  float64 `json:"V2Score,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				Custom9 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity22 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Ubuntu int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss10 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V2Vector string  `json:"V2Vector,omitempty"`
						V3Vector string  `json:"V3Vector,omitempty"`
						V2Score  float64 `json:"V2Score,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				Custom10 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity23 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss11 struct {
					Nvd struct {
						V3Vector  string  `json:"V3Vector,omitempty"`
						V40Vector string  `json:"V40Vector,omitempty"`
						V3Score   float64 `json:"V3Score,omitempty"`
						V40Score  float64 `json:"V40Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				DataSource1 struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
					URL  string `json:"URL,omitempty"`
				} `json:"DataSource,omitempty"`
				Custom11 struct {
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity24 struct {
					NodejsSecurityWg int `json:"nodejs-security-wg,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity25 struct {
					Ghsa     int `json:"ghsa,omitempty"`
					Nvd      int `json:"nvd,omitempty"`
					Redhat   int `json:"redhat,omitempty"`
					SuseCvrf int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity26 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Rocky      int `json:"rocky,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity27 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Rocky      int `json:"rocky,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity28 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity29 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Rocky      int `json:"rocky,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity30 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity31 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Rocky      int `json:"rocky,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity32 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity33 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Rocky      int `json:"rocky,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity34 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				DataSource2 struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
					URL  string `json:"URL,omitempty"`
				} `json:"DataSource,omitempty"`
				Custom12 struct {
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity35 struct {
					Ghsa int `json:"ghsa,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity36 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss12 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity37 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity38 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				DataSource3 struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
					URL  string `json:"URL,omitempty"`
				} `json:"DataSource,omitempty"`
				VendorSeverity39 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity40 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity41 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity42 struct {
					Alma       int `json:"alma,omitempty"`
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity43 struct {
					Alma       int `json:"alma,omitempty"`
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity44 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity45 struct {
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity46 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity47 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity48 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity49 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Custom13 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity50 struct {
					Ghsa int `json:"ghsa,omitempty"`
					Nvd  int `json:"nvd,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss13 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				VendorSeverity51 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity52 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity53 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity54 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity55 struct {
					Ghsa     int `json:"ghsa,omitempty"`
					Nvd      int `json:"nvd,omitempty"`
					Redhat   int `json:"redhat,omitempty"`
					SuseCvrf int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity56 struct {
					Ghsa   int `json:"ghsa,omitempty"`
					Nvd    int `json:"nvd,omitempty"`
					Redhat int `json:"redhat,omitempty"`
					Ubuntu int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity57 struct {
					Alma       int `json:"alma,omitempty"`
					Azure      int `json:"azure,omitempty"`
					CblMariner int `json:"cbl-mariner,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					Ubuntu     int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity58 struct {
					Ghsa             int `json:"ghsa,omitempty"`
					NodejsSecurityWg int `json:"nodejs-security-wg,omitempty"`
					Nvd              int `json:"nvd,omitempty"`
					Ubuntu           int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				Cvss14 struct {
					Ghsa struct {
						V3Vector string  `json:"V3Vector,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"ghsa,omitempty"`
					Nvd struct {
						V2Vector string  `json:"V2Vector,omitempty"`
						V3Vector string  `json:"V3Vector,omitempty"`
						V2Score  float64 `json:"V2Score,omitempty"`
						V3Score  float64 `json:"V3Score,omitempty"`
					} `json:"nvd,omitempty"`
				} `json:"CVSS,omitempty"`
				Custom14 struct {
					Epss struct {
						Date       string  `json:"Date,omitempty"`
						Percentile float64 `json:"Percentile,omitempty"`
						Score      float64 `json:"Score,omitempty"`
					} `json:"EPSS,omitempty"`
					DepPath    string `json:"depPath,omitempty"`
					Indirect   bool   `json:"indirect,omitempty"`
					LineNumber int    `json:"lineNumber,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity59 struct {
					Ghsa     int `json:"ghsa,omitempty"`
					Nvd      int `json:"nvd,omitempty"`
					Redhat   int `json:"redhat,omitempty"`
					SuseCvrf int `json:"suse-cvrf,omitempty"`
					Ubuntu   int `json:"ubuntu,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				DataSource4 struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
					URL  string `json:"URL,omitempty"`
				} `json:"DataSource,omitempty"`
				Custom15 struct {
					DepPath    string   `json:"depPath,omitempty"`
					Indirect   bool     `json:"indirect,omitempty"`
					LineNumber int      `json:"lineNumber,omitempty"`
					PkgRoots   []string `json:"pkgRoots,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity60 struct {
					NodejsSecurityWg int `json:"nodejs-security-wg,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				DataSource5 struct {
					ID   string `json:"ID,omitempty"`
					Name string `json:"Name,omitempty"`
					URL  string `json:"URL,omitempty"`
				} `json:"DataSource,omitempty"`
				Custom16 struct {
					DepPath    string   `json:"depPath,omitempty"`
					Indirect   bool     `json:"indirect,omitempty"`
					LineNumber int      `json:"lineNumber,omitempty"`
					PkgRoots   []string `json:"pkgRoots,omitempty"`
				} `json:"Custom,omitempty"`
				VendorSeverity61 struct {
					NodejsSecurityWg int `json:"nodejs-security-wg,omitempty"`
				} `json:"VendorSeverity,omitempty"`
				VendorSeverity62 struct {
					Alma       int `json:"alma,omitempty"`
					Ghsa       int `json:"ghsa,omitempty"`
					Nvd        int `json:"nvd,omitempty"`
					OracleOval int `json:"oracle-oval,omitempty"`
					Redhat     int `json:"redhat,omitempty"`
					SuseCvrf   int `json:"suse-cvrf,omitempty"`
				} `json:"VendorSeverity,omitempty"`
			} `json:"Vulnerabilities,omitempty"`
			MisconfSummary struct {
				Successes int `json:"Successes,omitempty"`
				Failures  int `json:"Failures,omitempty"`
			} `json:"MisconfSummary,omitempty"`
			Misconfigurations []struct {
				Type        string   `json:"Type,omitempty"`
				ID          string   `json:"ID,omitempty"`
				Avdid       string   `json:"AVDID,omitempty"`
				Title       string   `json:"Title,omitempty"`
				Description string   `json:"Description,omitempty"`
				Message     string   `json:"Message,omitempty"`
				Namespace   string   `json:"Namespace,omitempty"`
				Resolution  string   `json:"Resolution,omitempty"`
				Severity    string   `json:"Severity,omitempty"`
				PrimaryURL  string   `json:"PrimaryURL,omitempty"`
				References  []string `json:"References,omitempty"`
				Status      string   `json:"Status,omitempty"`
				Layer       struct {
				} `json:"Layer,omitempty"`
				CauseMetadata struct {
					Provider string `json:"Provider,omitempty"`
					Service  string `json:"Service,omitempty"`
					Code     struct {
						Lines any `json:"Lines,omitempty"`
					} `json:"Code,omitempty"`
					RenderedCause struct {
					} `json:"RenderedCause,omitempty"`
				} `json:"CauseMetadata,omitempty"`
			} `json:"Misconfigurations,omitempty"`
			Secrets []struct {
				RuleID    string `json:"RuleID,omitempty"`
				Category  string `json:"Category,omitempty"`
				Severity  string `json:"Severity,omitempty"`
				Title     string `json:"Title,omitempty"`
				StartLine int    `json:"StartLine,omitempty"`
				EndLine   int    `json:"EndLine,omitempty"`
				Code      struct {
					Lines []struct {
						Number      int    `json:"Number,omitempty"`
						Content     string `json:"Content,omitempty"`
						IsCause     bool   `json:"IsCause,omitempty"`
						Annotation  string `json:"Annotation,omitempty"`
						Truncated   bool   `json:"Truncated,omitempty"`
						Highlighted string `json:"Highlighted,omitempty"`
						FirstCause  bool   `json:"FirstCause,omitempty"`
						LastCause   bool   `json:"LastCause,omitempty"`
					} `json:"Lines,omitempty"`
				} `json:"Code,omitempty"`
				Match string `json:"Match,omitempty"`
				Layer struct {
				} `json:"Layer,omitempty"`
			} `json:"Secrets,omitempty"`
		} `json:"Results,omitempty"`
	} `json:"Report,omitempty"`
	Results []struct {
		Avdid     string `json:"AVDID,omitempty"`
		Message   string `json:"Message,omitempty"`
		Type      int    `json:"Type,omitempty"`
		Severity  int    `json:"Severity,omitempty"`
		Title     string `json:"Title,omitempty"`
		Filename  string `json:"Filename,omitempty"`
		StartLine int    `json:"StartLine,omitempty"`
		EndLine   int    `json:"EndLine,omitempty"`
		ExtraData struct {
			Category     string   `json:"Category,omitempty"`
			Owasp        []string `json:"OWASP,omitempty"`
			Technologies []string `json:"Technologies,omitempty"`
			Confidence   string   `json:"Confidence,omitempty"`
			Likelihood   string   `json:"Likelihood,omitempty"`
			Impact       string   `json:"Impact,omitempty"`
			References   []string `json:"References,omitempty"`
			Cwe          string   `json:"CWE,omitempty"`
			Fix          struct {
			} `json:"Fix,omitempty"`
			Remediation  string `json:"Remediation,omitempty"`
			Fingerprint  string `json:"Fingerprint,omitempty"`
			AiConfidence int    `json:"AiConfidence,omitempty"`
			AiReason     string `json:"AiReason,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData0 struct {
			Category     string   `json:"Category,omitempty"`
			Owasp        []string `json:"OWASP,omitempty"`
			Technologies []string `json:"Technologies,omitempty"`
			Confidence   string   `json:"Confidence,omitempty"`
			Likelihood   string   `json:"Likelihood,omitempty"`
			Impact       string   `json:"Impact,omitempty"`
			References   []string `json:"References,omitempty"`
			Cwe          string   `json:"CWE,omitempty"`
			Fix          struct {
			} `json:"Fix,omitempty"`
			Remediation   string `json:"Remediation,omitempty"`
			Fingerprint   string `json:"Fingerprint,omitempty"`
			DataflowTrace []struct {
				Start struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"Start,omitempty"`
				End struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"End,omitempty"`
			} `json:"DataflowTrace,omitempty"`
			AiConfidence int    `json:"AiConfidence,omitempty"`
			AiReason     string `json:"AiReason,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData1 struct {
			Category     string   `json:"Category,omitempty"`
			Owasp        []string `json:"OWASP,omitempty"`
			Technologies []string `json:"Technologies,omitempty"`
			Confidence   string   `json:"Confidence,omitempty"`
			Likelihood   string   `json:"Likelihood,omitempty"`
			Impact       string   `json:"Impact,omitempty"`
			References   []string `json:"References,omitempty"`
			Cwe          string   `json:"CWE,omitempty"`
			Fix          struct {
			} `json:"Fix,omitempty"`
			Remediation   string `json:"Remediation,omitempty"`
			Fingerprint   string `json:"Fingerprint,omitempty"`
			DataflowTrace []struct {
				Start struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"Start,omitempty"`
				End struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"End,omitempty"`
			} `json:"DataflowTrace,omitempty"`
			AiConfidence int    `json:"AiConfidence,omitempty"`
			AiReason     string `json:"AiReason,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData2 struct {
			Category     string   `json:"Category,omitempty"`
			Owasp        []string `json:"OWASP,omitempty"`
			Technologies []string `json:"Technologies,omitempty"`
			Confidence   string   `json:"Confidence,omitempty"`
			Likelihood   string   `json:"Likelihood,omitempty"`
			Impact       string   `json:"Impact,omitempty"`
			References   []string `json:"References,omitempty"`
			Cwe          string   `json:"CWE,omitempty"`
			Fix          struct {
			} `json:"Fix,omitempty"`
			Remediation   string `json:"Remediation,omitempty"`
			Fingerprint   string `json:"Fingerprint,omitempty"`
			DataflowTrace []struct {
				Start struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"Start,omitempty"`
				End struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"End,omitempty"`
			} `json:"DataflowTrace,omitempty"`
			AiConfidence int    `json:"AiConfidence,omitempty"`
			AiReason     string `json:"AiReason,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData3 struct {
			Category     string   `json:"Category,omitempty"`
			Owasp        []string `json:"OWASP,omitempty"`
			Technologies []string `json:"Technologies,omitempty"`
			Confidence   string   `json:"Confidence,omitempty"`
			Likelihood   string   `json:"Likelihood,omitempty"`
			Impact       string   `json:"Impact,omitempty"`
			References   []string `json:"References,omitempty"`
			Cwe          string   `json:"CWE,omitempty"`
			Fix          struct {
			} `json:"Fix,omitempty"`
			Remediation   string `json:"Remediation,omitempty"`
			Fingerprint   string `json:"Fingerprint,omitempty"`
			DataflowTrace []struct {
				Start struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"Start,omitempty"`
				End struct {
					Line   int `json:"Line,omitempty"`
					Col    int `json:"Col,omitempty"`
					Offset int `json:"Offset,omitempty"`
				} `json:"End,omitempty"`
			} `json:"DataflowTrace,omitempty"`
			AiConfidence int    `json:"AiConfidence,omitempty"`
			AiReason     string `json:"AiReason,omitempty"`
		} `json:"ExtraData,omitempty"`
		PkgName          string `json:"PkgName,omitempty"`
		InstalledVersion string `json:"InstalledVersion,omitempty"`
		FixedVersion     string `json:"FixedVersion,omitempty"`
		DataSource       string `json:"DataSource,omitempty"`
		VendorScoring    []struct {
			VendorName string  `json:"vendorName,omitempty"`
			V3Score    float64 `json:"V3Score,omitempty"`
			V3Vector   string  `json:"V3Vector,omitempty"`
			Severity   int     `json:"Severity,omitempty"`
		} `json:"VendorScoring,omitempty"`
		PublishedDate int `json:"PublishedDate,omitempty"`
		LastModified  int `json:"LastModified,omitempty"`
		ExtraData4    struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData5 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData6 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData7 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData8 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData9 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData10 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData11 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData12 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData13 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData14 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData15 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData16 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData17 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData18 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData19 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData20 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData21 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData22 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData23 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData24 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData25 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData26 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData27 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData28 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData29 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData30 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData31 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData32 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData33 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData34 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData35 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData36 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData37 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData38 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData39 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData40 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData41 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData42 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData43 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData44 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData45 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData46 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData47 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData48 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData49 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData50 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData51 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData52 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData53 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData54 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData55 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData56 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData57 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData58 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData59 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData60 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData61 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData62 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData63 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData64 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData65 struct {
			References []string `json:"References,omitempty"`
			Direct     string   `json:"Direct,omitempty"`
			Epss       struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData66 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData67 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData68 struct {
			References   []string `json:"References,omitempty"`
			Direct       string   `json:"Direct,omitempty"`
			PackageRoots []string `json:"PackageRoots,omitempty"`
			Epss         struct {
				Score      float64 `json:"Score,omitempty"`
				Percentile float64 `json:"Percentile,omitempty"`
				Date       string  `json:"Date,omitempty"`
			} `json:"EPSS,omitempty"`
		} `json:"ExtraData,omitempty"`
		Resource      string `json:"Resource,omitempty"`
		PolicyResults []struct {
			PolicyID      string   `json:"PolicyID,omitempty"`
			Enforced      bool     `json:"Enforced,omitempty"`
			Failed        bool     `json:"Failed,omitempty"`
			Reason        string   `json:"Reason,omitempty"`
			Controls      []string `json:"Controls,omitempty"`
			ControlResult []struct {
				Reason      string `json:"reason,omitempty"`
				Type        string `json:"type,omitempty"`
				MatchedData string `json:"matched_data,omitempty"`
				Location    string `json:"location,omitempty"`
				Name        string `json:"name,omitempty"`
			} `json:"ControlResult,omitempty"`
			PolicyName string `json:"policy_name,omitempty"`
		} `json:"PolicyResults,omitempty"`
		ExtraData69 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData70 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData71 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData72 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData73 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData74 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData75 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData76 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData77 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData78 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData79 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData80 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData81 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData82 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData83 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData84 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData85 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData86 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData87 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData88 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData89 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData90 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData91 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData92 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData93 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData94 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData95 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData96 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData97 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData98 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData99 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData100 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData101 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData102 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData103 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData104 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData105 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData106 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData107 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData108 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData109 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData110 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData111 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData112 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData113 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData114 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData115 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData116 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData117 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData118 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData119 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData120 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData121 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData122 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData123 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData124 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
		ExtraData125 struct {
			References []string `json:"References,omitempty"`
			Fix        struct {
				Resolution string `json:"Resolution,omitempty"`
			} `json:"Fix,omitempty"`
		} `json:"ExtraData,omitempty"`
	} `json:"Results,omitempty"`
}
