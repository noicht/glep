#!/usr/bin/env bash
# Test end-to-end contra el lab: levanta el target, corre GLEP en modo
# determinístico y valida el reporte JSON.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
GLEP="${ROOT}/.venv/bin/glep"
REPORT_DIR="${ROOT}/reports/smoke"
LAB_STARTED=0

cleanup() {
  if [[ "$LAB_STARTED" == "1" ]]; then
    "${ROOT}/lab/run_lab.sh" stop >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ ! -x "$GLEP" ]]; then
  echo "no existe $GLEP; instalá con: python -m pip install -e ." >&2
  exit 1
fi

"${ROOT}/lab/run_lab.sh" start
LAB_STARTED=1

rm -rf "$REPORT_DIR"
echo
echo "=== glep --check ==="
"$GLEP" --config "$ROOT/config/settings.lab.yaml" --check

echo
echo "=== glep run ==="
"$GLEP" \
  --config "$ROOT/config/settings.lab.yaml" \
  --target 127.0.0.1 \
  --report-dir "$REPORT_DIR" \
  --timeout 90 \
  --quiet

echo
echo "=== validando reporte ==="
"$PY" - "$REPORT_DIR" <<'PY'
import json
import pathlib
import sys

report_dir = pathlib.Path(sys.argv[1])
reports = sorted(report_dir.glob("glep-*.json"))
if not reports:
    raise SystemExit("no se generó ningún reporte JSON")

report = json.loads(reports[-1].read_text())
ports = set(report.get("open_ports", []))
expected = {18080, 12222, 16379}
missing = expected - ports
if missing:
    raise SystemExit(f"faltan puertos en el reporte: {sorted(missing)} (vistos: {sorted(ports)})")

findings = report.get("findings", [])
sqli = [f for f in findings if f.get("type") == "sql_injection_candidate"]
if not sqli:
    raise SystemExit("no se detectó el candidato de SQLi en /product?id=1")

if report.get("phase") != "DONE":
    raise SystemExit(f"el loop no terminó: {report.get('phase')}")

print(f"OK: {reports[-1].name}")
print(f"    puertos={sorted(ports)}")
print(f"    findings={len(findings)} (sql_injection_candidate={len(sqli)})")
PY

echo
echo "=== resumen del reporte ==="
sed -n '1,60p' "$(ls -t "$REPORT_DIR"/*.md | head -1)"
echo
echo "smoke test OK"
