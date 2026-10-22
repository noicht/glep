#!/usr/bin/env python3
"""Benchmark mínimo de LLMPolicy para decidir si corre en la Pi.

Mide tiempo de carga, RSS máximo y latencia por decisión. No es un
benchmark de calidad: para eso mirá qué acciones elige contra el lab.

    .venv/bin/python scripts/bench_llm.py
    .venv/bin/python scripts/bench_llm.py --runs 5 --n-ctx 512 --threads 2
"""

import argparse
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from glep.policy.llm import LLMPolicy  # noqa: E402
from glep.state import EngagementState  # noqa: E402


def rss_mb() -> float:
    # Linux: ru_maxrss en KiB.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=str(ROOT / "models/Qwen2.5-0.5B-Instruct-Q3_K_M.gguf"))
    parser.add_argument("--grammar", default=str(ROOT / "grammar/tool_call.gbnf"))
    parser.add_argument("--n-ctx", type=int, default=512)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    if not Path(args.model).is_file():
        print(f"modelo no encontrado: {args.model}", file=sys.stderr)
        return 2

    print(f"cargando {Path(args.model).name} (n_ctx={args.n_ctx}, threads={args.threads})")
    start = time.perf_counter()
    policy = LLMPolicy(
        model_path=args.model,
        grammar_path=args.grammar,
        n_ctx=args.n_ctx,
        n_threads=args.threads,
        timeout_seconds=args.timeout,
    )
    load_seconds = time.perf_counter() - start
    print(f"carga: {load_seconds:.2f}s  rss_max={rss_mb():.1f} MB")

    state = EngagementState(
        target_host="127.0.0.1",
        target_port_range="12000-19999",
        open_ports=[18080, 12222, 16379],
        services={18080: "http Apache httpd 2.4.49", 12222: "ssh OpenSSH 7.4"},
        urls=["http://127.0.0.1:18080/product?id=1"],
    )

    latencies: list[float] = []
    actions: list[dict | None] = []
    for index in range(args.runs):
        start = time.perf_counter()
        try:
            action = policy._decide_with_llm(state)
        except Exception as exc:
            action = None
            print(f"run {index + 1}: error {type(exc).__name__}: {exc}")
        elapsed = time.perf_counter() - start
        latencies.append(elapsed)
        actions.append(action)
        print(f"run {index + 1}: {elapsed:.2f}s  action={json.dumps(action, ensure_ascii=False)}")

    if latencies:
        print(
            f"latencia: min={min(latencies):.2f}s "
            f"prom={sum(latencies) / len(latencies):.2f}s "
            f"max={max(latencies):.2f}s"
        )
    print(f"rss_max final: {rss_mb():.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
