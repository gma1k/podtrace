#!/bin/bash
set -euo pipefail

CRD="${CRD:-podtraces.podtrace.io}"
NS="${NAMESPACE:?NAMESPACE must be set by chainsaw}"

served_raw=$(kubectl get crd "${CRD}" -o jsonpath='{range .spec.versions[?(@.served==true)]}{.name}{"\n"}{end}')
mapfile -t SERVED <<<"${served_raw}"
STORAGE=$(kubectl get crd "${CRD}" -o jsonpath='{range .spec.versions[?(@.storage==true)]}{.name}{end}')

if [[ "${#SERVED[@]}" -lt 2 ]]; then
	echo "ok: ${CRD} serves only ${SERVED[0]}; cross-version round-trip is trivially satisfied"
	exit 0
fi

OTHER=""
for v in "${SERVED[@]}"; do
	if [[ "${v}" != "${STORAGE}" ]]; then
		OTHER="${v}"
		break
	fi
done
echo "storage version: ${STORAGE}; also serving: ${OTHER}"

RESOURCE="${CRD%%.*}"
GROUP="${CRD#*.}"

kubectl apply -f - <<YAML
apiVersion: ${GROUP}/${STORAGE}
kind: PodTrace
metadata:
  name: roundtrip
  namespace: ${NS}
spec:
  selector:
    matchLabels:
      app: roundtrip
  exporterRef:
    name: roundtrip-otlp
  filters: [dns, net]
  samplePercent: 20
  thresholds:
    errorRatePercent: 10
    rttSpikeMs: 250
    filesystemLatencyMs: 100
YAML

canonical_spec() {
	local raw
	raw=$(kubectl get "${RESOURCE}.${1}.${GROUP}" roundtrip -n "${NS}" -o json)
	jq -S '.spec' <<<"${raw}"
}

canonical_status() {
	local raw
	raw=$(kubectl get "${RESOURCE}.${1}.${GROUP}" roundtrip -n "${NS}" -o json)
	jq -S '.status // {}' <<<"${raw}"
}

STORAGE_SPEC=$(canonical_spec "${STORAGE}")
OTHER_SPEC=$(canonical_spec "${OTHER}")

if [[ "${STORAGE_SPEC}" != "${OTHER_SPEC}" ]]; then
	echo "FAIL: reading through ${OTHER} returns a different spec than ${STORAGE}" >&2
	diff <(echo "${STORAGE_SPEC}") <(echo "${OTHER_SPEC}") >&2 || true
	exit 1
fi
echo "ok: spec round-trips unchanged between ${STORAGE} and ${OTHER}"

kubectl apply -f - >/dev/null <<YAML
apiVersion: ${GROUP}/${OTHER}
kind: PodTrace
metadata:
  name: roundtrip
  namespace: ${NS}
spec:
  selector:
    matchLabels:
      app: roundtrip
  exporterRef:
    name: roundtrip-otlp
  filters: [dns, net]
  samplePercent: 20
  thresholds:
    errorRatePercent: 10
    rttSpikeMs: 250
    filesystemLatencyMs: 100
YAML

AFTER_APPLY=$(canonical_spec "${STORAGE}")
if [[ "${AFTER_APPLY}" != "${STORAGE_SPEC}" ]]; then
	echo "FAIL: a client-side apply through ${OTHER} changed the stored object" >&2
	diff <(echo "${STORAGE_SPEC}") <(echo "${AFTER_APPLY}") >&2 || true
	exit 1
fi
echo "ok: client-side apply through ${OTHER} dropped nothing"

kubectl apply --server-side --force-conflicts --field-manager=roundtrip-gitops -f - >/dev/null <<YAML
apiVersion: ${GROUP}/${OTHER}
kind: PodTrace
metadata:
  name: roundtrip
  namespace: ${NS}
spec:
  selector:
    matchLabels:
      app: roundtrip
  exporterRef:
    name: roundtrip-otlp
  filters: [dns, net]
  samplePercent: 20
  thresholds:
    errorRatePercent: 10
    rttSpikeMs: 250
    filesystemLatencyMs: 100
YAML

AFTER_SSA=$(canonical_spec "${STORAGE}")
if [[ "${AFTER_SSA}" != "${STORAGE_SPEC}" ]]; then
	echo "FAIL: server-side apply --force-conflicts through ${OTHER} changed the stored object" >&2
	diff <(echo "${STORAGE_SPEC}") <(echo "${AFTER_SSA}") >&2 || true
	exit 1
fi
echo "ok: server-side apply --force-conflicts through ${OTHER} dropped nothing"

STORAGE_STATUS=$(canonical_status "${STORAGE}")
OTHER_STATUS=$(canonical_status "${OTHER}")
if [[ "${STORAGE_STATUS}" != "${OTHER_STATUS}" ]]; then
	echo "FAIL: status differs between ${STORAGE} and ${OTHER}" >&2
	diff <(echo "${STORAGE_STATUS}") <(echo "${OTHER_STATUS}") >&2 || true
	exit 1
fi
echo "ok: status round-trips unchanged"
