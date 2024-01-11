package vulnr

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/go-github/v58/github"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/cveawg"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/utils"
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

func MapCVE(cve *cveawg.CVE, trivyCVE *cveawg.TrivyCVE) *Vulnerability {
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

	if trivyCVE != nil {
		for _, url := range trivyCVE.Urls {
			if url == "" {
				continue
			}

			vulnr.References = append(vulnr.References, url)
		}

		additional := Details{Title: "Additional", Items: []Item{
			{Title: "CVSS", Value: trivyCVE.Cvss},
			{Title: "Score", Value: fmt.Sprintf("%.2f", trivyCVE.Score)},
			{Title: "Severity", Value: trivyCVE.Severity},
			{Title: "Published", Value: trivyCVE.CreatedAt.Format(time.RFC3339)},
		}}

		affected := utils.Map(trivyCVE.AffectedVersion, func(v cveawg.AffectedVersion) string {
			if v.To != "" {
				return fmt.Sprintf("%s - %s", v.From, v.To)
			}
			return v.From
		})
		fixed := utils.Map(trivyCVE.FixedVersion, func(v cveawg.FixedVersion) string {
			return v.Fixed
		})

		if len(affected) > 0 {
			additional.Items = append(additional.Items, Item{Title: "Affected Versions", Value: strings.Join(affected, ", ")})
			additional.Items = append(additional.Items, Item{Title: "Fixed Versions", Value: strings.Join(fixed, ", ")})
		}

		vulnr.Details = append(vulnr.Details, additional)

		return vulnr
	}

	vulnr.Details = append(vulnr.Details, Details{Title: "Additional", Items: []Item{
		{Title: "Assigner", Value: cve.CveMetadata.AssignerShortName},
		{Title: "Published", Value: cve.CveMetadata.DatePublished},
	}})

	affected := Details{Title: "Affected Versions", Items: make([]Item, 0)}
	for _, a := range cve.Containers.Cna.Affected {
		for _, v := range a.Versions {
			value := v.Version
			if v.LessThan != "" {
				value = fmt.Sprintf("from %s before %s", v.Version, v.LessThan)
			}

			affected.Items = append(affected.Items, Item{Title: a.Product, Value: value})
		}
	}

	for _, ref := range cve.Containers.Cna.References {
		vulnr.References = append(vulnr.References, ref.URL)
	}

	vulnr.Details = append(vulnr.Details, affected)

	return vulnr
}

func toValue[T any](v *T) T {
	var value T
	if v == nil {
		return value
	}

	return *v
}
