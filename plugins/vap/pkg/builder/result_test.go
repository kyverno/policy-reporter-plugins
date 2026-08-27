package builder

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/audit"
)

func TestBuild_Deny(t *testing.T) {
	ev := audit.Event{
		HasAudit: false,
		Time:     time.Unix(1700000000, 0),
		Resource: audit.Resource{
			APIGroup: "apps", Resource: "deployments", Namespace: "default", Name: "web",
		},
	}
	r := audit.Result{
		Policy:  "require-labels",
		Binding: "require-labels-binding",
		Message: "labels are required",
		Action:  audit.ActionDeny,
	}

	result := Build(ev, r, Options{})

	assert.EqualValues(t, "fail", result.Result)
	assert.True(t, result.Scored, "expected Deny to be scored")
	assert.Equal(t, "require-labels", result.Policy)
	assert.Equal(t, "require-labels-binding", result.Rule)
	assert.NotEmpty(t, result.Properties["resultID"])
	assert.Equal(t, "Deny", result.Properties["action"])
}

func TestBuild_Audit(t *testing.T) {
	idx := 2
	ev := audit.Event{HasAudit: true}
	r := audit.Result{
		Policy:          "min-replicas",
		Binding:         "min-replicas-binding",
		Message:         "replicas too low",
		ExpressionIndex: &idx,
		Action:          audit.ActionAudit,
	}

	result := Build(ev, r, Options{})

	assert.EqualValues(t, "fail", result.Result)
	assert.False(t, result.Scored, "expected Audit action to be unscored")
	assert.Equal(t, "2", result.Properties["expressionIndex"])
}

func TestResultID_StableAndDistinct(t *testing.T) {
	ev := audit.Event{
		Resource: audit.Resource{
			APIGroup: "apps", Resource: "deployments", Namespace: "default", Name: "web",
		},
	}
	base := audit.Result{Policy: "p1", Binding: "b1"}
	other := base
	other.Policy = "p2"

	require.NotEqual(t, ResultID(ev, base), ResultID(ev, other), "expected different policies to produce different resultIDs")
}
