{{- define "vap-plugin.fullname" -}}
vap-plugin
{{- end -}}

{{- define "vap-plugin.labels" -}}
app.kubernetes.io/name: vap-plugin
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
