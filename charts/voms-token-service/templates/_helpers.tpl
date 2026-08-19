{{/*
Expand the name of the chart.
*/}}
{{- define "voms-token-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name, truncated at 63 chars (DNS spec).
If the release name contains the chart name it will be used as a full name.
*/}}
{{- define "voms-token-service.fullname" -}}
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
{{- define "voms-token-service.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource in this chart.
*/}}
{{- define "voms-token-service.labels" -}}
helm.sh/chart: {{ include "voms-token-service.chart" . }}
{{ include "voms-token-service.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/part-of: af-mcp-platform
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels (stable — used in matchLabels; do not add mutable fields here).
*/}}
{{- define "voms-token-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "voms-token-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Image reference.
*/}}
{{- define "voms-token-service.image" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Path to the IGTF certificates directory as exported by X509_CERT_DIR,
baked in by the Containerfile's pixi shell-hook entrypoint
(activate-ca-policy-lcg.sh sets X509_CERT_DIR=$CONDA_PREFIX/etc/grid-security/certificates,
and CONDA_PREFIX is fixed at /app/.pixi/envs/service — see Containerfile).
When crlRefresh is enabled, a writable emptyDir is mounted over this exact
path so refresh_crls.sh can rewrite the *.r0 CRL files despite
readOnlyRootFilesystem; must match X509_CERT_DIR byte-for-byte or the
overlay shadows the wrong directory.
*/}}
{{- define "voms-token-service.certificatesPath" -}}
/app/.pixi/envs/service/etc/grid-security/certificates
{{- end }}
