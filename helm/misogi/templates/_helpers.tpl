{{/*
=============================================================================
Misogi Helm Chart — Template Helpers
=============================================================================
Standard helper templates for consistent naming, labeling, and selector
generation across all Misogi Kubernetes resources.
*/}}

{{/* Generate standard Kubernetes labels for Misogi resources. */}}
{{- define "misogi.labels" -}}
app.kubernetes.io/name: {{ include "misogi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: misogi
helm.sh/chart: "{{ .Chart.Name }}-{{ .Chart.Version }}"
{{- end -}}

{{/* Generate match label selectors for pod selection. */}}
{{- define "misogi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "misogi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Resolve the full chart name (handles nameOverride / fullNameOverride). */}}
{{- define "misogi.name" -}}
{{- default .Chart.Name .Values.fullNameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Resolve the full resource name including release name. */}}
{{- define "misogi.fullname" -}}
{{- if .Values.fullNameOverride -}}
{{- .Values.fullNameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Component-specific fullnames and labels. */}}
{{- define "misogi.sender.fullname" -}}
{{- printf "%s-sender" (include "misogi.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "misogi.sender.labels" -}}
{{ include "misogi.labels" . }}
app.kubernetes.io/component: sender
{{- end -}}

{{- define "misogi.sender.selectorLabels" -}}
{{ include "misogi.selectorLabels" . }}
app.kubernetes.io/component: sender
{{- end -}}

{{- define "misogi.receiver.fullname" -}}
{{- printf "%s-receiver" (include "misogi.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "misogi.receiver.labels" -}}
{{ include "misogi.labels" . }}
app.kubernetes.io/component: receiver
{{- end -}}

{{- define "misogi.receiver.selectorLabels" -}}
{{ include "misogi.selectorLabels" . }}
app.kubernetes.io/component: receiver
{{- end -}}

{{- define "misogi.smtp.fullname" -}}
{{- printf "%s-smtp" (include "misogi.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "misogi.smtp.labels" -}}
{{ include "misogi.labels" . }}
app.kubernetes.io/component: smtp
{{- end -}}

{{- define "misogi.smtp.selectorLabels" -}}
{{ include "misogi.selectorLabels" . }}
app.kubernetes.io/component: smtp
{{- end -}}

{{/* ServiceAccount name helper. */}}
{{- define "misogi.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "misogi.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
