import argparse
import sys
from pathlib import Path

import yaml

from glep import __version__
from glep.logger import get_logger
from glep.loop import ReactLoop
from glep.policy.deterministic import DeterministicPolicy
from glep.report import write_report
from glep.scope import ScopeError, check_target
from glep.state import EngagementState
from glep.tools import tool_availability

_DEFAULT_CONFIG = "config/settings.yaml"


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    return resolve_config_paths(config, path)


def resolve_config_paths(config: dict, config_path: str) -> dict:
    """Resuelve rutas relativas contra la raíz del proyecto (el directorio
    padre de `config/`), para que `glep --config /ruta/config/settings.yaml`
    funcione desde cualquier cwd."""
    base = Path(config_path).resolve().parent
    if base.name == "config":
        base = base.parent

    def resolve(value: str | None) -> str | None:
        if not value:
            return value
        path = Path(value).expanduser()
        return str(path if path.is_absolute() else (base / path).resolve())

    config.setdefault("logging", {})
    config["logging"]["file"] = resolve(config["logging"].get("file", "./logs/glep.log"))

    config.setdefault("report", {})
    config["report"]["dir"] = resolve(config["report"].get("dir", "./reports"))

    config.setdefault("llm", {})
    for key in ("model_path", "grammar_path"):
        if key in config["llm"]:
            config["llm"][key] = resolve(config["llm"][key])

    config.setdefault("tools", {})
    wordlists = config["tools"].setdefault("wordlists", {})
    for key in ("users", "passwords"):
        if key in wordlists:
            wordlists[key] = resolve(wordlists[key])

    return config


def _deterministic_from_config(config: dict) -> DeterministicPolicy:
    policy_cfg = config.get("policy", {})
    wordlists = config.get("tools", {}).get("wordlists", {})
    return DeterministicPolicy(
        allow_exploit=bool(policy_cfg.get("allow_exploit", True)),
        allow_bruteforce=bool(policy_cfg.get("allow_bruteforce", False)),
        max_http_probes=int(policy_cfg.get("max_http_probes", 20)),
        userlist=wordlists.get("users", "/opt/glep/wordlists/users.txt"),
        passlist=wordlists.get("passwords", "/opt/glep/wordlists/passwords.txt"),
    )


def build_policy(config: dict, logger, mode: str | None = None):
    policy_cfg = config.get("policy", {})
    mode = mode or policy_cfg.get("mode", "deterministic")

    if mode == "deterministic":
        return _deterministic_from_config(config)

    if mode == "llm":
        try:
            from glep.policy.llm import LLMPolicy

            llm_cfg = config.get("llm", {})
            policy_cfg = config.get("policy", {})
            return LLMPolicy(
                model_path=llm_cfg["model_path"],
                grammar_path=llm_cfg["grammar_path"],
                n_ctx=int(llm_cfg.get("n_ctx", 512)),
                n_threads=int(llm_cfg.get("n_threads", 4)),
                timeout_seconds=int(llm_cfg.get("timeout_seconds", 15)),
                logger=logger,
                allow_exploit=bool(policy_cfg.get("allow_exploit", True)),
                allow_bruteforce=bool(policy_cfg.get("allow_bruteforce", False)),
            )
        except Exception:
            if not policy_cfg.get("fallback_to_deterministic", True):
                raise
            logger.exception(
                "No se pudo inicializar LLMPolicy; usando DeterministicPolicy"
            )
            return _deterministic_from_config(config)

    raise ValueError(f"policy.mode desconocido: {mode}")


def _preflight(config: dict, logger) -> dict[str, dict]:
    availability = tool_availability()
    missing = [
        name for name, info in availability.items() if not info["available"]
    ]
    if missing:
        logger.warning("Binarios faltantes: %s (esas tools se omiten)", ", ".join(missing))
    return availability


def _print_check(config: dict, scope, availability: dict[str, dict], target: str, port_range: str) -> None:
    policy_cfg = config.get("policy", {})
    print(f"GLEP {__version__}")
    print(f"target: {target}  puertos: {port_range}")
    print(f"scope: {scope.kind} {scope.addresses} -> {'OK' if scope.allowed else 'BLOQUEADO'}")
    print(f"       {scope.reason}")
    print(f"policy: {policy_cfg.get('mode', 'deterministic')}")
    print("tools:")
    for name, info in availability.items():
        state = "ok" if info["available"] else "FALTA"
        print(f"  {name:<8} {state:<6} ({info['binary']})")
    print(f"log: {config.get('logging', {}).get('file')}")
    print(f"reports: {config.get('report', {}).get('dir')}")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="glep",
        description="GLEP — agente de pentesting para objetivos autorizados.",
    )
    parser.add_argument("--config", default=_DEFAULT_CONFIG)
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("--target", help="host/IP objetivo (override de la config)")
    parser.add_argument("--port-range", help='rango nmap, ej. "1-1024"')
    parser.add_argument(
        "--policy",
        choices=("deterministic", "llm"),
        help="override de policy.mode",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="confirmás que tenés autorización para el target (obligatorio en LAN/público)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="preflight: muestra scope, tools instaladas y config, sin escanear",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="lista tools y si el binario está instalado",
    )
    parser.add_argument("--report-dir", help="override de report.dir")
    parser.add_argument("--no-report", action="store_true", help="no escribir reporte")
    parser.add_argument("--log-file", help="override de logging.file")
    parser.add_argument("--max-iterations", type=int, help="tope de acciones del loop")
    parser.add_argument("--timeout", type=int, help="timeout por tool en segundos")
    parser.add_argument("--verbose", action="store_true", help="log también a stderr")
    parser.add_argument("--quiet", action="store_true", help="no imprimir resumen final")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.list_tools:
        for name, info in tool_availability().items():
            state = "ok" if info["available"] else "MISSING"
            print(f"{name:<8} {state:<8} {info['binary']}")
        return 0

    try:
        config = load_config(args.config)
    except (OSError, yaml.YAMLError) as exc:
        print(f"glep: no se pudo leer {args.config}: {exc}", file=sys.stderr)
        return 2

    target = args.target or config.get("target", {}).get("host")
    if not target:
        print("glep: falta target.host en la config o --target", file=sys.stderr)
        return 2

    port_range = (
        args.port_range
        or config.get("target", {}).get("port_range")
        or "1-1024"
    )
    policy_mode = args.policy or config.get("policy", {}).get("mode", "deterministic")

    if args.report_dir:
        config["report"]["dir"] = args.report_dir
    if args.log_file:
        config["logging"]["file"] = args.log_file

    target_cfg = config.get("target", {})
    try:
        scope = check_target(
            target,
            authorized=bool(args.authorized or target_cfg.get("authorized", False)),
            allow_public=bool(target_cfg.get("allow_public", False)),
        )
    except ScopeError as exc:
        print(f"glep: {exc}", file=sys.stderr)
        return 2

    if not scope.allowed:
        print(f"glep: target fuera de alcance: {scope.reason}", file=sys.stderr)
        return 2

    logger = get_logger(
        "glep",
        config.get("logging", {}).get("file"),
        config.get("logging", {}).get("level", "INFO"),
        console=args.verbose,
    )
    availability = _preflight(config, logger)

    if args.check:
        _print_check(config, scope, availability, target, port_range)
        return 0

    logger.info(
        "Inicio target=%s (%s) port_range=%s policy=%s",
        target,
        ", ".join(scope.addresses),
        port_range,
        policy_mode,
    )

    try:
        policy = build_policy(config, logger, mode=policy_mode)
    except Exception as exc:
        logger.exception("No se pudo construir la policy")
        print(f"glep: no se pudo construir la policy: {exc}", file=sys.stderr)
        return 1

    state = EngagementState(
        target_host=target,
        target_port_range=port_range,
        web_port_hints=[int(p) for p in target_cfg.get("web_ports", [])],
    )

    loop = ReactLoop(
        policy=policy,
        logger=logger,
        max_iterations=args.max_iterations
        or int(config.get("loop", {}).get("max_iterations", 200)),
        tool_timeout_seconds=args.timeout
        or int(config.get("tools", {}).get("timeout_seconds", 120)),
        allow_exploit=bool(config.get("policy", {}).get("allow_exploit", True)),
        allow_bruteforce=bool(config.get("policy", {}).get("allow_bruteforce", False)),
    )

    try:
        final_state = loop.run(state)
    except KeyboardInterrupt:
        logger.warning("Interrumpido por el usuario")
        return 130

    json_path = md_path = None
    if not args.no_report:
        try:
            json_path, md_path = write_report(
                final_state,
                config.get("report", {}).get("dir", "./reports"),
                scope={
                    "host": scope.host,
                    "addresses": scope.addresses,
                    "kind": scope.kind,
                    "allowed": scope.allowed,
                    "reason": scope.reason,
                    "authorized_flag": bool(args.authorized),
                },
                policy_mode=policy_mode,
            )
        except OSError as exc:
            logger.exception("No se pudo escribir el reporte")
            print(f"glep: no se pudo escribir el reporte: {exc}", file=sys.stderr)

    logger.info(
        "Terminado. fase=%s puertos_abiertos=%s findings=%s",
        final_state.phase.name,
        final_state.open_ports,
        len(final_state.findings),
    )

    if not args.quiet:
        print(
            f"GLEP {__version__} target={target} phase={final_state.phase.name} "
            f"ports={final_state.open_ports or 'none'} "
            f"findings={len(final_state.findings)}"
        )
        if md_path:
            print(f"report: {md_path}")
        elif not args.no_report:
            print("report: no escrito")

    return 0


if __name__ == "__main__":
    sys.exit(main())
