# kyverno-plugin

Kyverno Plugin for Policy Reporter UI

![Version: 0.0.1](https://img.shields.io/badge/Version-0.0.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.2](https://img.shields.io/badge/AppVersion-0.0.2-informational?style=flat-square)

## Documentation

You can find detailed Information and Screens about Features and Configurations in the [Documentation](https://kyverno.github.io/policy-reporter).

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| replicaCount | int | `1` |  |
| app.logging | object | `{"encoding":"console","logLevel":0}` | App logging configuration |
| app.logging.encoding | string | `"console"` | log encoding possible encodings are console and json |
| app.logging.logLevel | int | `0` | log level default info |
| app.server | object | `{"basicAuth":{"password":"","secretRef":"","username":""},"logging":false,"port":8080}` | App server configuration |
| app.server.port | int | `8080` | Application port |
| app.server.logging | bool | `false` | Enables Access logging |
| app.server.basicAuth | object | `{"password":"","secretRef":"","username":""}` | Enables HTTP Basic Authentication |
| app.server.basicAuth.username | string | `""` | HTTP BasicAuth username |
| app.server.basicAuth.password | string | `""` | HTTP BasicAuth password |
| app.server.basicAuth.secretRef | string | `""` | Read credentials from secret |
| app.blockReports | object | `{"enabled":false,"eventNamespace":"default","results":{"keepOnlyLatest":false,"maxPerReport":200}}` | BlockRepoort Feature configuration |
| app.blockReports.enabled | bool | `false` | Enables he BlockReport feature |
| app.blockReports.eventNamespace | string | `"default"` | Watches for Kyverno Events in the configured namespace leave blank to watch in all namespaces |
| app.blockReports.results.maxPerReport | int | `200` | Max items per PolicyReport resource |
| app.blockReports.results.keepOnlyLatest | bool | `false` | Keep only the latest of duplicated events |
| image.registry | string | `"ghcr.io"` | Image registry |
| image.repository | string | `"kyverno/policy-reporter/kyverno-plugin"` | Image repository |
| image.pullPolicy | string | `"IfNotPresent"` | Image PullPolicy |
| image.tag | string | `""` | Image tag Defaults to `Chart.AppVersion` if omitted |
| imagePullSecrets | list | `[]` | Image pull secrets for image verification policies, this will define the `--imagePullSecrets` argument |
| nameOverride | string | `""` | Override the name of the chart |
| fullnameOverride | string | `""` | Override the expanded name of the chart |
| serviceAccount.create | bool | `true` | Create ServiceAccount |
| serviceAccount.automount | bool | `true` | Enable ServiceAccount automaount |
| serviceAccount.annotations | object | `{}` | Annotations for the ServiceAccount |
| serviceAccount.name | string | `""` | The ServiceAccount name |
| podAnnotations | object | `{}` | Additional annotations to add to each pod |
| podLabels | object | `{}` | Additional labels to add to each pod |
| updateStrategy | object | `{}` | Deployment update strategy. Ref: https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#strategy |
| revisionHistoryLimit | int | `10` | The number of revisions to keep |
| podSecurityContext | object | `{"runAsGroup":1234,"runAsUser":1234}` | Security context for the pod |
| envVars | list | `[]` | Allow additional env variables to be added |
| rbac.enabled | bool | `true` | Create RBAC resources |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"privileged":false,"readOnlyRootFilesystem":true,"runAsNonRoot":true,"runAsUser":1234,"seccompProfile":{"type":"RuntimeDefault"}}` | Container security context |
| service.type | string | `"ClusterIP"` | Service type. |
| service.port | int | `8080` | Service port. |
| service.annotations | object | `{}` | Service annotations. |
| service.labels | object | `{}` | Service labels. |
| ingress.enabled | bool | `false` | Create ingress resource. |
| ingress.className | string | `""` | Ingress class name. |
| ingress.labels | object | `{}` | Ingress labels. |
| ingress.annotations | object | `{}` | Ingress annotations. |
| ingress.hosts | list | `[]` | List of ingress host configurations. |
| ingress.tls | list | `[]` | List of ingress TLS configurations. |
| networkPolicy.enabled | bool | `false` | When true, use a NetworkPolicy to allow ingress to the webhook This is useful on clusters using Calico and/or native k8s network policies in a default-deny setup. |
| networkPolicy.egress | list | `[{"ports":[{"port":6443,"protocol":"TCP"}]}]` | A list of valid from selectors according to https://kubernetes.io/docs/concepts/services-networking/network-policies. Enables Kubernetes API Server by default |
| networkPolicy.ingress | list | `[]` | A list of valid from selectors according to https://kubernetes.io/docs/concepts/services-networking/network-policies. |
| resources | object | `{}` |  |
| leaderElection.enabled | bool | `false` | Enables LeaderElection. |
| leaderElection.lockName | string | `"kyverno-plugin"` | Lock Name |
| leaderElection.releaseOnCancel | bool | `true` | Released lock when the run context is cancelled. |
| leaderElection.leaseDuration | int | `15` | LeaseDuration is the duration that non-leader candidates will wait to force acquire leadership. |
| leaderElection.renewDeadline | int | `10` | RenewDeadline is the duration that the acting master will retry refreshing leadership before giving up. |
| leaderElection.retryPeriod | int | `2` | RetryPeriod is the duration the LeaderElector clients should wait between tries of actions. |
| podDisruptionBudget.minAvailable | int | `1` | Configures the minimum available pods for kyvernoPlugin disruptions. Cannot be used if `maxUnavailable` is set. |
| podDisruptionBudget.maxUnavailable | string | `nil` | Configures the maximum unavailable pods for kyvernoPlugin disruptions. Cannot be used if `minAvailable` is set. |
| nodeSelector | object | `{}` | Node labels for pod assignment |
| tolerations | list | `[]` | List of node taints to tolerate |
| affinity | object | `{}` | Affinity constraints. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)