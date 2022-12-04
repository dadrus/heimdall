{{/*
Expand the name of the chart.
*/}}
{{- define "heimdall.demo.name" -}}
{{- $name := printf "%s-demo" (default .Chart.Name .Values.nameOverride) -}}
{{- $name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "heimdall.demo.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- $name := printf "%s-demo" .Values.fullnameOverride -}}
{{- $name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := printf "%s-demo" (default .Chart.Name .Values.nameOverride) }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common demo labels
*/}}
{{- define "heimdall.demo.labels" -}}
{{ include "heimdall.demo.selectorLabels" . }}
helm.sh/chart: {{ include "heimdall.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ include "heimdall.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "heimdall.demo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "heimdall.name" . }}-demo-app
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


