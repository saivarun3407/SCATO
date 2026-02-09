{{/*
Expand the name of the chart.
*/}}
{{- define "scato.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "scato.fullname" -}}
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
{{- define "scato.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "scato.labels" -}}
helm.sh/chart: {{ include "scato.chart" . }}
{{ include "scato.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "scato.selectorLabels" -}}
app.kubernetes.io/name: {{ include "scato.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "scato.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "scato.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL construction
*/}}
{{- define "scato.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "scato.fullname" .) .Values.postgresql.auth.database }}
{{- else if .Values.externalDatabase.host }}
{{- printf "postgresql://%s:%s@%s:%d/%s" .Values.externalDatabase.user .Values.externalDatabase.password .Values.externalDatabase.host (.Values.externalDatabase.port | int) .Values.externalDatabase.database }}
{{- end }}
{{- end }}

{{/*
Redis URL construction
*/}}
{{- define "scato.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis-master:6379" (include "scato.fullname" .) }}
{{- else if .Values.externalRedis.host }}
{{- if .Values.externalRedis.password }}
{{- printf "redis://:%s@%s:%d" .Values.externalRedis.password .Values.externalRedis.host (.Values.externalRedis.port | int) }}
{{- else }}
{{- printf "redis://%s:%d" .Values.externalRedis.host (.Values.externalRedis.port | int) }}
{{- end }}
{{- end }}
{{- end }}
