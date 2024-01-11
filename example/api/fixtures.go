package api

import (
	"github.com/kyverno/policy-reporter-plugins/sdk/api"
)

var (
	policies = []api.PolicyListItem{
		{
			Category:    "Optional Policy Category",
			Title:       "Human readable title of the policy",
			Name:        "unique-policy-name is used to fetch policy detauls from the API",
			Severity:    "severity: info | low | medium | high | critical",
			Description: "optional policy description",
		},
		{
			Category:    "Pod Security Standards (Baseline)",
			Title:       "Disallow Capabilities",
			Name:        "disallow-capabilities",
			Severity:    "medium",
			Description: "Adding capabilities beyond those listed in the policy must be disallowed.",
		},
		{
			Category:    "Pod Security Standards (Restricted)",
			Title:       "Disallow Capabilities (Strict)",
			Name:        "disallow-capabilities-strict",
			Severity:    "medium",
			Description: "Adding capabilities other than `NET_BIND_SERVICE` is disallowed. In addition, all containers must explicitly drop `ALL` capabilities.",
		},
	}

	details = map[string]*api.Policy{
		"disallow-capabilities": {
			Category:    "Pod Security Standards (Baseline)",
			Title:       "Disallow Capabilities",
			Name:        "disallow-capabilities",
			Severity:    "medium",
			Description: "Adding capabilities beyond those listed in the policy must be disallowed.",
			Engine: &api.Engine{
				Name:     "Kyverno",
				Version:  "1.6.0",
				Subjects: []string{"Pod"},
			},
			SourceCode: &api.SourceCode{
				ContentType: "yaml",
				Content: `➜  kyverno kc get cpol disallow-capabilities -o yaml
				apiVersion: kyverno.io/v1
				kind: ClusterPolicy
				metadata:
				  annotations:
					kyverno.io/kyverno-version: 1.6.0
					policies.kyverno.io/category: Pod Security Standards (Baseline)
					policies.kyverno.io/description: Adding capabilities beyond those listed in the
					  policy must be disallowed.
					policies.kyverno.io/minversion: 1.6.0
					policies.kyverno.io/severity: medium
					policies.kyverno.io/subject: Pod
					policies.kyverno.io/title: Disallow Capabilities
				  name: disallow-capabilities
				  resourceVersion: "4098941"
				  uid: 267a3066-2683-4712-a49a-5c0e2a8a106d
				spec:
				  admission: true
				  background: true
				  failurePolicy: Fail
				  rules:
				  - match:
					  any:
					  - resources:
						  kinds:
						  - Pod
					name: adding-capabilities
					preconditions:
					  all:
					  - key: '{{ request.operation || ''BACKGROUND'' }}'
						operator: NotEquals
						value: DELETE
					validate:
					  deny:
						conditions:
						  all:
						  - key: '{{ request.object.spec.[ephemeralContainers, initContainers, containers][].securityContext.capabilities.add[]
							  }}'
							operator: AnyNotIn
							value:
							- AUDIT_WRITE
							- CHOWN
							- DAC_OVERRIDE
							- FOWNER
							- FSETID
							- KILL
							- MKNOD
							- NET_BIND_SERVICE
							- SETFCAP
							- SETGID
							- SETPCAP
							- SETUID
							- SYS_CHROOT
					  message: Any capabilities added beyond the allowed list (AUDIT_WRITE, CHOWN,
						DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID,
						SETPCAP, SETUID, SYS_CHROOT) are disallowed.
				  validationFailureAction: Audit`,
			},
			Details: []api.DetailsItem{
				{Title: "Background", Value: "true"},
				{Title: "Admission", Value: "true"},
				{Title: "FailurePolicy", Value: "Fail"},
				{Title: "Mode", Value: "Audit"},
			},
		},

		"CVE-2022-41723": {
			Title:       "CVE-2022-41723",
			Name:        "CVE-2022-41723",
			Description: "A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient to cause a denial of service from a small number of small requests.",
			Category:    "",
			References: []api.Reference{
				{URL: "https://go.dev/issue/57855"},
				{URL: "https://go.dev/cl/468135"},
			},
			Details: []api.DetailsItem{
				{Title: "Assigner", Value: "Go"},
				{Title: "Pblished", Value: "2023-02-28T17:19:45.801Z"},
			},
			Additional: []api.Details{
				{
					Title: "Affected Versions",
					Items: []api.DetailsItem{
						{Title: "net/http", Value: "from 0 before 1.19.6"},
						{Title: "golang.org/x/net/http2", Value: "from 0 before 0.7.0"},
					},
				},
			},
		},

		"min": {
			Title:       "CVE-2022-41723",
			Name:        "CVE-2022-41723",
			Description: "A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient to cause a denial of service from a small number of small requests.",
		},
	}
)
