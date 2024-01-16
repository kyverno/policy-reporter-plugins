# Setup Kyverno and Policy Reporter

## Install Kyverno + Kyverno PSS Policies

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

## Installing Policy Reporter Preview 3.x with the UI and Kyverno Plugin

```bash
helm repo add policy-reporter https://kyverno.github.io/policy-reporter
helm repo update
```

Install the Policy Reporter Preview

```bash
helm upgrade --install policy-reporter policy-reporter/policy-reporter-preview --create-namespace -n policy-reporter --devel --set ui.enabled=true --set kyverno-plugin.enabled=true
```
