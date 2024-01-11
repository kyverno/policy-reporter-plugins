package vulnr

import (
	"github.com/kyverno/policy-reporter-plugins/sdk/api"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/utils"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/vulnr"
)

func MapVulnrToDetails(v *vulnr.Vulnerability) *api.Policy {
	details := &api.Policy{
		Category:    v.Category,
		Name:        v.ID,
		Title:       v.Title,
		Description: v.Description,
		Severity:    v.Severity,
		Details:     make([]api.DetailsItem, 0),
		References:  make([]api.Reference, 0, len(v.References)),
		Engine: &api.Engine{
			Name:     "Trivy",
			Subjects: []string{"Pod", "ReplicaSet"},
		},
	}

	for _, ref := range v.References {
		if ref == "" {
			continue
		}

		details.References = append(details.References, api.Reference{URL: ref})
	}

	for _, d := range v.Details {
		if d.Title == "Additional" {
			for _, i := range d.Items {
				details.Details = append(details.Details, api.DetailsItem{Title: i.Title, Value: i.Value})
			}

			continue
		}

		details.Additional = append(details.Additional, api.Details{
			Title: d.Title,
			Items: utils.Map(d.Items, func(i vulnr.Item) api.DetailsItem {
				return api.DetailsItem{Title: i.Title, Value: i.Value}
			}),
		})
	}

	return details
}
