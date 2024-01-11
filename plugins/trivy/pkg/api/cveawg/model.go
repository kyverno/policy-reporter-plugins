package cveawg

import "time"

type CVE struct {
	Containers  Containers  `json:"containers"`
	CveMetadata CveMetadata `json:"cveMetadata"`
	DataType    string      `json:"dataType"`
	DataVersion string      `json:"dataVersion"`
}

type Containers struct {
	Cna Cna `json:"cna"`
}

type CveMetadata struct {
	AssignerOrgID     string `json:"assignerOrgId"`
	AssignerShortName string `json:"assignerShortName"`
	CveID             string `json:"cveId"`
	DatePublished     string `json:"datePublished"`
	DateReserved      string `json:"dateReserved"`
	DateUpdated       string `json:"dateUpdated"`
	State             string `json:"state"`
}

type Versions struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	LessThan string `json:"lessThan"`
}

type Affected struct {
	Product  string     `json:"product"`
	Vendor   string     `json:"vendor"`
	Versions []Versions `json:"versions"`
}

type References struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags"`
	URL  string   `json:"url"`
}

type Cvss struct {
	AttackComplexity      string  `json:"attackComplexity"`
	AttackVector          string  `json:"attackVector"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	Scope                 string  `json:"scope"`
	UserInteraction       string  `json:"userInteraction"`
	VectorString          string  `json:"vectorString"`
	Version               string  `json:"version"`
}

type Impact struct {
	Cvss Cvss `json:"cvss"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Cna struct {
	Affected     []Affected    `json:"affected"`
	DatePublic   string        `json:"datePublic"`
	Descriptions []Description `json:"descriptions"`
	References   []References  `json:"references"`
	Title        string        `json:"title"`
}

type TrivyCVE struct {
	ID              string            `json:"id"`
	CreatedAt       time.Time         `json:"created_at"`
	Summary         string            `json:"summary"`
	Component       string            `json:"component"`
	Description     string            `json:"description"`
	AffectedVersion []AffectedVersion `json:"affected_version"`
	FixedVersion    []FixedVersion    `json:"fixed_version"`
	Urls            []string          `json:"urls"`
	Cvss            string            `json:"cvss"`
	Severity        string            `json:"severity"`
	Score           float64           `json:"score"`
}

type AffectedVersion struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type FixedVersion struct {
	Fixed string `json:"fixed"`
}
