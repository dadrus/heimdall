{{/*
Helper to traverse dicts with a dot-notation string.
Usage:
  {{ fn.get .Values "foo.bar.baz" }}
*/}}
{{- define "fn.get" -}}
  {{- $vals := index . 0 -}}
  {{- $path := index . 1 -}}
  {{- $parts := splitList "." $path -}}
  {{- $current := $vals -}}
  {{- range $parts }}
    {{- $current = get $current . -}}
  {{- end -}}
  {{- /* Serialize so caller can deserialize to structured data */ -}}
{{- $current | toYaml -}}
{{- end -}}


{{/*
Expand the name of the chart.
*/}}
{{- define "heimdall.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "heimdall.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "heimdall.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create namesapce.
*/}}
{{- define "heimdall.namespace" -}}
{{- if .Release.Namespace -}}
  {{ .Release.Namespace | default "default" }}
{{- end -}}
{{- end }}

{{/*
Common labels
*/}}
{{- define "heimdall.labels" -}}
helm.sh/chart: {{ include "heimdall.chart" . }}
{{ include "heimdall.selectorLabels" . }}
  {{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
  {{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
  {{- if .Component -}}
    {{- $component := include "fn.get" (list .Values .Component) | fromYaml -}}
    {{- if $component -}}
      {{- range $key, $value := $component.labels }}
{{ $key }}: {{ $value | quote }}
      {{- end -}}
    {{- end -}}
  {{- end -}}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "heimdall.selectorLabels" -}}
app.kubernetes.io/name: {{ include "heimdall.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component annotations
*/}}
{{- define "heimdall.annotations" -}}
  {{- if .Component -}}
    {{- $component := include "fn.get" (list .Values .Component) | fromYaml -}}
    {{- if $component -}}
      {{- range $key, $value := $component.annotations }}
{{ $key }}: {{ $value | quote }}
      {{- end -}}
    {{- end -}}
  {{- end -}}
{{- end }}

{{/*
Component service
*/}}
{{- define "heimdall.service" -}}
{{- $baseName := include "heimdall.fullname" . -}}
{{- if eq .Component "service.default" -}}
  {{- $baseName -}}
{{- else if eq .Component "service.validationWebhook" -}}
  {{- printf "%s-validation" $baseName | trunc 63 | trimSuffix "-" -}}
{{- else if eq .Component "service.conversionWebhook" -}}
  {{- $hash := .Values.crds.targetVersion | sha256sum | trunc 8 -}}
  {{- printf "%s-%s" $baseName $hash | trunc 63 | trimSuffix "-" -}}
{{- else -}}
  {{- fail "internal error: unknown component specified in heimdall.service helper!" -}}
{{- end -}}
{{- end -}}


