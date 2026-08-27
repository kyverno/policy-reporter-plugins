# vap-plugin

Watches Kubernetes API server audit log entries produced by
`ValidatingAdmissionPolicy` (VAP) evaluations and persists them as
[`openreports.io/v1alpha1`](https://github.com/openreports/reports-api)
`Report`/`ClusterReport` custom resources - one per audited resource - so VAP
compliance data shows up in the same reporting surface as every other policy
engine (e.g. [Policy Reporter](https://github.com/kyverno/policy-reporter)).

VAP is a native Kubernetes admission mechanism, so unlike Kyverno it does not
generate `PolicyReport`/`Report` objects on its own. This app fills that gap.

## How it works

```
kube-apiserver (VAP admission)
   │  static --audit-policy-file + --audit-webhook-config-file
   ▼
pkg/webhook   HTTPS receiver for audit.k8s.io/v1 EventList batches
   ▼
pkg/audit     extracts VAP results from each event
   ▼
pkg/builder   converts them to openreports.io ReportResult
   ▼
pkg/kubernetes/report   upserts the Report/ClusterReport that scopes
                         the audited resource
```

A periodic sweep (`pkg/kubernetes/reconcile`) cleans up reports whose target
resource is gone and reconciles labels/annotations after a config change -
see "Report lifecycle" below for why this, rather than Kubernetes' built-in
garbage collection, is the primary cleanup path. It always runs; with
`leaderElection.enabled`, it's coordinated to a single replica via a Lease
(required when running more than one replica, otherwise every replica
sweeps independently).

## What's observable in the audit log

Verified against `k8s.io/apiserver`'s `ValidatingAdmissionPolicy` admission
plugin source, and against a real audit log captured from a kind cluster
(k8s v1.36.1) running actual `Deny`- and `Audit`-action policy bindings:

- **`Deny` action** (blocking): the request is rejected. There is no
  `validation.policy.admission.k8s.io/validation_failure` audit annotation
  for this path - that's only set for `Audit`-action failures. The signal is
  the audit event's `responseStatus`, whose `.details.causes[].message`
  holds the unwrapped VAP message (`responseStatus.message` itself wraps it
  in a resource-specific prefix, e.g. `pods "x" is forbidden: <msg>`, so
  causes is checked first, with message as a fallback).
- **`Audit` action** (log-but-allow): sets the annotation
  `validation.policy.admission.k8s.io/validation_failure` to a JSON array of
  `{message, policy, binding, expressionIndex, validationActions}` - this
  matched the real captured payload exactly.
- **`Warn` action**: emits an HTTP `Warning` response header only, which is
  not part of the audit event schema - not currently supported.
- **"Pass" results**: no event carries a positive "this policy passed"
  signal. This app does not attempt to report passes (see "Known
  limitations").

## Report lifecycle

Each `Report`/`ClusterReport` scopes exactly one audited resource. Every
audit event yields a batch of results (everything `pkg/audit.Parse`
extracted from it - all sharing that event's target resource), and
`report.Client.Upsert` takes the whole batch in one call and replaces the
Report's `Results` with it wholesale, not merges into what was there
before: each event is a fresh, complete evaluation of the resource's
current state, so a policy result left over from an earlier event but
absent from this batch (its binding no longer matches, or it just wasn't
re-evaluated) is dropped, not carried forward as stale history. This also
means one `Get`/`Update` round trip persists an entire event's worth of
results, not one per individual policy result.

When a Report is created,
`pkg/kubernetes/report` does a live `GET` of that resource via the dynamic
client and uses the real UID from there. This
covers the common case (the resource exists and RBAC permits reading it -
by default just `pods`, see `rbac.extraResources` / `deploy/rbac.yaml`, since
that's what VAP most commonly targets; add any other resource type your
policies match). This lookup only runs when the whole batch is Audit-only:
if any result in it is Deny, the overall request was rejected (VAP denies
the whole request if any binding denies), so the lookup is skipped
entirely for the batch - not attempted-and-failed, skipped outright - even
if other, unrelated bindings in the same batch are Audit-action (a single
audit event can carry both: an Audit-action binding's failure is still
recorded even when a different binding's Deny is what rejected the
request). For a Create this is moot anyway since the resource never
existed; it's also not worth a live GET on an Update/Delete Deny. Any
resource type without RBAC to read it falls back the same way as a failed
lookup would.

`OwnerReference` is therefore best-effort, not the primary cleanup
mechanism: it can't cover every case, so it isn't relied on alone. Every
upsert also stamps a `vap-plugin.io/last-observed` annotation, and the
reconcile sweep deletes any ownerless managed report that hasn't been
touched within a configurable TTL (default 24h, see `reconcile.orphanTTL`) -
the one mechanism that covers every case, including the ones OwnerReference
can't.

## Reporting Deny results

`report.reportDenied` (default `false`) controls whether `Deny`-action
results are persisted at all. A `Deny` already surfaces to the caller as a
rejected request - `kubectl` prints the rejection message directly - so by
default only `Audit`-action results are reported, since those are the ones
that would otherwise go unnoticed (the request is allowed through silently).
Set it to `true` to also persist `Deny`-action results.

The filtering happens in `pkg/audit.Parse` itself (its `reportDenied`
parameter, threaded through from `pkg/webhook.Server`), before an `Event`
is ever handed to `pkg/kubernetes/report` - not as a later post-processing
step there. It's a whole-event decision, not a per-result filter: a single
audit event can carry both a `Deny` and an unrelated `Audit`-action failure
together (see "What's observable in the audit log"), and with
`reportDenied: false` that entire event is dropped - the co-occurring
`Audit` result is discarded along with the `Deny`, not persisted on its
own (see `pkg/audit`'s `TestParse_MixedEventDroppedEntirelyWhenReportDeniedDisabled`).
`Parse` returns a zero `Event` (empty `Results`) in this case, so
`pkg/webhook.Server` never calls `Client.Upsert` for it at all - not a
create, not an update - which also means an existing Report from an
earlier, unrelated event on the same resource is left untouched, not
cleared out. An event with no `Deny` result at all is never affected by
this setting: with `reportDenied: true`, both `Deny` and `Audit` results
are tracked, from every event, unfiltered.

## Result severity & category

Every `ReportResult` gets a severity and a category: `report.severity` /
`report.category` in config set the app-wide defaults (both empty by
default, since VAP has no built-in concept of either). A
`ValidatingAdmissionPolicy` can override either per-policy by annotating
itself:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-team-label
  annotations:
    vap.kubernetes.io/severity: high
    vap.kubernetes.io/category: best-practices
```

`vap.kubernetes.io/severity` accepts `critical`, `high`, `medium`, `low`,
`info` - matching `openreports.io/v1alpha1.ResultSeverity`'s enum exactly.
An invalid or unrecognized value is treated the same as no annotation
(falls back to the configured default), never passed through: the API
server would otherwise reject the whole Report update over one bad field,
not just skip it, since that enum is enforced by the CRD.

`vap.kubernetes.io/category` has no such enum - `ReportResult.Category` is
a free-form string, so any non-empty value is accepted as-is.

Both are resolved via `pkg/kubernetes/policy.MetadataLookup`, a single
informer-backed cache over `ValidatingAdmissionPolicy` objects shared by
both lookups (RBAC: `get,list,watch`, already included in
`deploy/rbac.yaml`/the Helm chart) - not a live API call per audit event,
since evaluations happen far more often than policies change. Getting this
right took a real bug fix: an earlier version passed the same context to
both the informer's lifetime and its startup sync deadline, so the deferred
cancel at the end of the constructor killed the informer's watch moments
after startup. It only ever saw the (empty) initial list and silently
missed every policy created afterward - overrides just never took effect,
with no error anywhere pointing at why. See `policy.NewMetadataLookup`'s
doc comment.

## Policy Reporter plugin API

Alongside the audit webhook receiver, vap-plugin serves the
[Policy Reporter plugin API](https://github.com/kyverno/policy-reporter-plugins/blob/main/sdk/api/model.go)
(the same contract implemented by the Kyverno and Trivy plugins) on its own
plain-HTTP listener (`api.port`, default `8080` - separate from the TLS
audit webhook receiver on `server.port`, since the two serve unrelated
purposes and Kubernetes' audit webhook backend requires HTTPS while the
plugin API does not):

- `GET /v1/policies` - lists every `ValidatingAdmissionPolicy` in the
  cluster.
- `GET /v1/policies/<name>` - returns one policy's details, including its
  full source as YAML.

There is no exception-generation endpoint: unlike Kyverno,
`ValidatingAdmissionPolicy` has no `PolicyException` equivalent.

A `ValidatingAdmissionPolicy` can annotate itself to control how it's
presented, in addition to `vap.kubernetes.io/severity` and
`vap.kubernetes.io/category` (see "Result severity & category" above):

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-team-label
  annotations:
    vap.kubernetes.io/title: "Require Team Label"
    vap.kubernetes.io/description: "Pods must carry a non-empty team label."
    vap.kubernetes.io/subject: "Pod, Deployment"
```

`vap.kubernetes.io/title` falls back to a title-cased version of the policy
name when absent; `vap.kubernetes.io/subject` is a comma-separated list
shown as the policy's engine subjects.

A policy's listed severity/category falls back to the app-wide
`report.severity`/`report.category` config when it has no
`vap.kubernetes.io/severity`/`vap.kubernetes.io/category` annotation of its
own - the same fallback applied to that policy's actual ReportResults (see
"Result severity & category" above), so what the plugin API shows always
matches what's reported.

Optional HTTP basic auth for this listener is configured under `api.basicAuth`
(`deploy/config.example.yaml`) - both `username` and `password` must be set
for it to take effect.

## Configuration

See [`deploy/config.example.yaml`](deploy/config.example.yaml) for all
options (server/TLS, webhook buffering, report labels, leader election,
reconcile interval/TTL, logging).

## Cluster wiring

The audit webhook backend is wired statically into the API server, per
[`deploy/audit-policy.yaml`](deploy/audit-policy.yaml) (the audit policy -
`level: Metadata` is sufficient for both signals above) and
[`deploy/audit-webhook-kubeconfig.yaml`](deploy/audit-webhook-kubeconfig.yaml)
(the `--audit-webhook-config-file`). This is operator-managed; there's no
in-cluster API to register it dynamically since Kubernetes removed the
`AuditSink` API. RBAC is in [`deploy/rbac.yaml`](deploy/rbac.yaml) (also
available as the `charts/vap-plugin` Helm chart).

## Development

```sh
make build   # builds ./vap-plugin
make test    # go test ./... -race -cover
make vet
```

`vap-plugin run --kubeconfig <path>` runs against any reachable cluster for
local testing (defaults to in-cluster config).

For a full local end-to-end setup - a kind cluster with the audit webhook,
CRDs, RBAC, and vap-plugin itself all wired up, plus sample VAP policies to
trigger - see [`scripts/setup.sh`](scripts/setup.sh) (`./scripts/setup.sh`,
`./scripts/setup.sh teardown`). It documents (and works around) several real
gotchas discovered while building and actually running it, not assumed:
`kube-apiserver`'s `hostNetwork` means Service DNS names don't resolve for
the webhook config; `audit-webhook-mode: blocking` deadlocks cluster
bootstrap; a cluster-wide `Deny` binding with no namespace exclusion
permanently blocks every future rollout of vap-plugin's own pod, not just
its first creation; and a fixed image tag means Helm/Kubernetes never
notices a rebuilt image and silently keeps the old pod running, which is
why the script uses `ko`'s resolved digest instead.

## Known limitations

- `Warn`-action VAP failures are not currently captured (see above).
- No "pass" reporting: computing that requires independently evaluating
  policy `matchConstraints` against every request, not just parsing what
  the audit log already tells you. `k8s.io/apiserver/pkg/admission/plugin/policy/matching`
  is importable and could provide this as a follow-up, at the cost of
  running `ValidatingAdmissionPolicy`/`ValidatingAdmissionPolicyBinding`
  informers and re-implementing request matching.
