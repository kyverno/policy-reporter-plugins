# Setup Trivy Operator Polr Adapter and Policy Reporter

## Install Trivy Operator

Add Helm Repository

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
```

Installation of the Trivy Operator

```bash
helm upgrade --install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace --set="trivy.ignoreUnfixed=true"
```

## (Optional) Install Kyverno + Kyverno PSS Policies

Add Helm Repo

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
```

Install Kyverno + PSS Policies

```bash
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace
helm upgrade --install kyverno-policies kyverno/kyverno-policies -n kyverno --create-namespace --set podSecurityStandard=restricted
```

## Install Trivy Operator Polr Adapter

Maps Trivy Operator CRDs into the unified PolicyReport and ClusterPolicyReport from the Kubernetes Policy Working Group. This makes it possible to use tooling like [Policy Reporter](https://github.com/kyverno/policy-reporter) for the different kinds of Trivy Reports.

```bash
helm repo add trivy-operator-polr-adapter https://fjogeleit.github.io/trivy-operator-polr-adapter
helm repo update
```

The default installation maps `VulnerabilityReports` and `ConfigAuditReports`. If you want to enable additional reports check out the [docs](https://github.com/fjogeleit/trivy-operator-polr-adapter) of the adapter.

Set `crds.install` to `true` is needed if you not have the PolicyReport and ClusterPolicyReport CRD installed. Both should be available if you running e.g. Kyverno as well.

### With Kyverno

```bash
helm install trivy-operator-polr-adapter trivy-operator-polr-adapter/trivy-operator-polr-adapter -n trivy-system
```

### Without Kyverno (install PolicyReport CRDs)

```bash
helm install trivy-operator-polr-adapter trivy-operator-polr-adapter/trivy-operator-polr-adapter --set crds.install=true -n trivy-system
```

## Installing Policy Reporter Preview 3.x with the UI and Trivy Plugin

```bash
helm repo add policy-reporter https://kyverno.github.io/policy-reporter
helm repo update
```

Install the Policy Reporter Preview

### With Kyverno (Kyverno Plugin enabled)

```bash
helm upgrade --install policy-reporter policy-reporter/policy-reporter-preview --create-namespace -n policy-reporter --devel --set ui.enabled=true --set trivy-plugin.enabled=true --set kyverno-plugin.enabled=true
```

### Without Kyverno

```bash
helm upgrade --install policy-reporter policy-reporter/policy-reporter-preview --create-namespace -n policy-reporter --devel --set ui.enabled=true --set trivy-plugin.enabled=true
```