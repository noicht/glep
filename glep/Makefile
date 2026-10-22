PY := .venv/bin/python
GLEP := .venv/bin/glep
CONFIG := config/settings.yaml

.PHONY: install test check lab-up lab-down lab-status smoke bench-llm run

install:
	python3 -m venv .venv
	$(PY) -m pip install -e '.[dev]'

test:
	$(PY) -m pytest

check:
	$(GLEP) --config $(CONFIG) --check

lab-up:
	./lab/run_lab.sh start

lab-down:
	./lab/run_lab.sh stop

lab-status:
	./lab/run_lab.sh status

smoke:
	./scripts/smoke_test.sh

bench-llm:
	$(PY) scripts/bench_llm.py

run:
	$(GLEP) --config $(CONFIG)
