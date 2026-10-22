"""Reporte del engagement: JSON (para máquinas) + Markdown (para humanos).

No es un informe de consultoría: es el volcado auditable de qué se probó,
qué se encontró y qué tools no estaban disponibles. Sirve para comparar
corridas y para que el operador valide los findings a mano.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from glep import __version__
from glep.state import EngagementState

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_report(
    state: EngagementState,
    scope: dict | None = None,
    policy_mode: str = "unknown",
) -> dict:
    return {
        "meta": {
            "tool": "glep",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "policy_mode": policy_mode,
            "scope": scope or {},
            "disclaimer": (
                "Ejecutado sobre un objetivo autorizado. Los findings son "
                "indicadores automáticos y requieren validación manual."
            ),
        },
        **state.summary(),
    }


def write_report(
    state: EngagementState,
    report_dir: str | Path,
    scope: dict | None = None,
    policy_mode: str = "unknown",
) -> tuple[Path, Path]:
    directory = Path(report_dir)
    directory.mkdir(parents=True, exist_ok=True)

    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", state.target_host) or "target"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"glep-{safe_host}-{stamp}"

    report = build_report(state, scope=scope, policy_mode=policy_mode)

    json_path = directory / f"{stem}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md_path = directory / f"{stem}.md"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    meta = report.get("meta", {})
    counts = report.get("severity_counts", {})

    lines.append(f"# GLEP report — `{report.get('target_host', '?')}`")
    lines.append("")
    lines.append(f"- **Fecha:** {meta.get('generated_at', '?')}")
    lines.append(f"- **Versión:** {meta.get('version', '?')}")
    lines.append(f"- **Policy:** {meta.get('policy_mode', '?')}")
    scope = meta.get("scope") or {}
    if scope:
        lines.append(
            f"- **Alcance:** {scope.get('kind', '?')} "
            f"({', '.join(scope.get('addresses', []))}) — {scope.get('reason', '')}"
        )
    lines.append(
        f"- **Rango de puertos:** {report.get('target_port_range', '?')}"
    )
    lines.append("")

    lines.append("## Resumen")
    lines.append("")
    if counts:
        lines.append("| Severidad | Cantidad |")
        lines.append("|---|---:|")
        for severity in _SEVERITY_ORDER:
            if severity in counts:
                lines.append(f"| {severity} | {counts[severity]} |")
    else:
        lines.append("Sin findings.")
    lines.append("")

    lines.append("## Puertos abiertos")
    lines.append("")
    ports = report.get("open_ports", [])
    services = report.get("services", {})
    if ports:
        lines.append("| Puerto | Servicio |")
        lines.append("|---:|---|")
        for port in ports:
            lines.append(f"| {port} | {services.get(str(port), 'unknown')} |")
    else:
        lines.append("No se detectaron puertos abiertos.")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    findings = report.get("findings", [])
    if not findings:
        lines.append("Sin findings automáticos.")
        lines.append("")
    else:
        for finding in sorted(
            findings,
            key=lambda item: _SEVERITY_ORDER.index(
                str(item.get("severity", "info")).lower()
            )
            if str(item.get("severity", "info")).lower() in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
        ):
            severity = str(finding.get("severity", "info")).upper()
            type_ = finding.get("type", "finding")
            lines.append(f"### [{severity}] `{type_}`")
            target = finding.get("url") or finding.get("host") or ""
            if target:
                lines.append(f"- **Target:** `{target}`")
            if finding.get("port"):
                lines.append(f"- **Puerto:** {finding['port']}")
            if finding.get("parameter"):
                lines.append(f"- **Parámetro:** `{finding['parameter']}`")
            if finding.get("evidence"):
                lines.append(f"- **Evidencia:** {finding['evidence']}")
            if finding.get("source"):
                lines.append(f"- **Fuente:** {finding['source']}")
            lines.append("")

    lines.append("## URLs descubiertas")
    lines.append("")
    urls = report.get("urls", [])
    if urls:
        for url in urls:
            lines.append(f"- `{url}`")
    else:
        lines.append("Ninguna.")
    lines.append("")

    lines.append("## Acciones ejecutadas")
    lines.append("")
    actions = report.get("actions", [])
    if actions:
        lines.append("| Tool | Args | RC | Nota |")
        lines.append("|---|---|---:|---|")
        for action in actions:
            args = json.dumps(action.get("args", {}), ensure_ascii=False)
            note = action.get("skipped", "")
            if action.get("timed_out"):
                note = "timeout"
            lines.append(
                f"| {action.get('tool', '?')} | `{args}` | "
                f"{action.get('returncode', '')} | {note} |"
            )
    else:
        lines.append("Ninguna.")
    lines.append("")

    errors = report.get("errors", [])
    if errors:
        lines.append("## Errores / limitaciones")
        lines.append("")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append("## Disclaimer")
    lines.append("")
    lines.append(meta.get("disclaimer", ""))
    lines.append("")
    return "\n".join(lines)
