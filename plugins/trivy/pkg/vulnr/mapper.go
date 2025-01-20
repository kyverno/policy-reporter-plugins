package vulnr

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/google/go-github/v58/github"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/cveawg"
)

func MapSecurityAdvisory(ghsa *github.GlobalSecurityAdvisory) *Vulnerability {
	vulnr := &Vulnerability{
		ID:          toValue(ghsa.GHSAID),
		Title:       toValue(ghsa.Summary),
		Description: toValue(ghsa.Description),
		Details:     make([]Details, 0),
		References:  ghsa.References,
	}

	additional := Details{Title: "Additional", Items: []Item{}}

	if ghsa.CVSS != nil {
		additional.Items = append(additional.Items, Item{Title: "CVSS Score", Value: fmt.Sprintf("%.2f", toValue(ghsa.CVSS.Score))})
		additional.Items = append(additional.Items, Item{Title: "CVSS VectorString", Value: toValue(ghsa.CVSS.VectorString)})
	}

	additional.Items = append(additional.Items, Item{Title: "Published", Value: toValue(ghsa.PublishedAt).Format(time.RFC3339)})
	additional.Items = append(additional.Items, Item{Title: "Severity", Value: toValue(ghsa.Severity)})

	vulnr.Details = append(vulnr.Details, additional)

	for _, v := range ghsa.Vulnerabilities {
		vulnr.Details = append(vulnr.Details, Details{Title: toValue(v.Package.Name), Items: []Item{
			{Title: "Ecosystem", Value: toValue(v.Package.Ecosystem)},
			{Title: "First Patched", Value: toValue(v.FirstPatchedVersion)},
			{Title: "Version Range", Value: toValue(v.VulnerableVersionRange)},
			{Title: "Functions", Value: strings.Join(v.VulnerableFunctions, ",")},
		}})
	}

	return vulnr
}

func MapCVE(cve *cveawg.CVE, trivyCVE *types.Vulnerability) *Vulnerability {
	vulnr := &Vulnerability{
		ID:         cve.CveMetadata.CveID,
		Title:      cve.CveMetadata.CveID,
		Details:    make([]Details, 0),
		References: make([]string, 0),
	}

	if len(cve.Containers.Cna.Descriptions) == 1 {
		vulnr.Description = cve.Containers.Cna.Descriptions[0].Value
	} else {
		for _, d := range cve.Containers.Cna.Descriptions {
			if d.Lang == "en" {
				vulnr.Description = d.Value
			}
		}
	}

	affected := Details{Title: "Affected Versions", Items: make([]Item, 0)}
	for _, a := range cve.Containers.Cna.Affected {
		for _, v := range a.Versions {
			if v.Version == "n/a" {
				continue
			}

			value := v.Version
			if v.LessThan != "" {
				value = fmt.Sprintf("from %s before %s", v.Version, v.LessThan)
			}

			affected.Items = append(affected.Items, Item{Title: a.Product, Value: value})
		}
	}

	if trivyCVE != nil && trivyCVE.PublishedDate != nil {
		vulnr.Details = append(vulnr.Details, Details{Title: "Additional", Items: []Item{
			{Title: "Assigner", Value: cve.CveMetadata.AssignerShortName},
			{Title: "Published", Value: trivyCVE.PublishedDate.Format(time.RFC3339)},
		}})
	} else {
		vulnr.Details = append(vulnr.Details, Details{Title: "Additional", Items: []Item{
			{Title: "Assigner", Value: cve.CveMetadata.AssignerShortName},
			{Title: "Published", Value: cve.CveMetadata.DatePublished},
		}})
	}

	if trivyCVE != nil {
		if len(trivyCVE.CweIDs) > 0 {
			vulnr.Details[0].Items = append(vulnr.Details[0].Items, Item{Title: "CWE IDs", Value: strings.Join(trivyCVE.CweIDs, ", ")})
		}

		for _, url := range trivyCVE.References {
			if url == "" {
				continue
			}

			vulnr.References = append(vulnr.References, url)
		}

		for vendor, cvss := range trivyCVE.CVSS {
			details := Details{Title: fmt.Sprintf("%s CVSS", vendor), Items: make([]Item, 0)}

			if cvss.V2Score != 0 {
				details.Items = append(details.Items, Item{Title: "V2 Score", Value: fmt.Sprintf("%.2f", cvss.V2Score)})
			}
			if cvss.V3Score != 0 {
				details.Items = append(details.Items, Item{Title: "V3 Score", Value: fmt.Sprintf("%.2f", cvss.V3Score)})
			}
			if cvss.V40Score != 0 {
				details.Items = append(details.Items, Item{Title: "V40 Score", Value: fmt.Sprintf("%.2f", cvss.V40Score)})
			}
			if cvss.V2Vector != "" {
				details.Items = append(details.Items, Item{Title: "V2 Vector", Value: cvss.V2Vector})
			}
			if cvss.V3Vector != "" {
				details.Items = append(details.Items, Item{Title: "V3 Vector", Value: cvss.V3Vector})
			}
			if cvss.V40Vector != "" {
				details.Items = append(details.Items, Item{Title: "V40 Vector", Value: cvss.V40Vector})
			}

			vulnr.Details = append(vulnr.Details, details)
		}

		vulnr.Title = cve.CveMetadata.CveID
		vulnr.Description = trivyCVE.Description
	} else {
		for _, ref := range cve.Containers.Cna.References {
			vulnr.References = append(vulnr.References, ref.URL)
		}
	}

	if len(affected.Items) > 0 {
		vulnr.Details = append(vulnr.Details, affected)
	}

	return vulnr
}

func toValue[T any](v *T) T {
	var value T
	if v == nil {
		return value
	}

	return *v
}
