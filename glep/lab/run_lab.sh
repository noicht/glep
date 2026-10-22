#!/usr/bin/env bash
# Levanta/baja el target vulnerable del lab (contenedor aislado).
#
#   lab/run_lab.sh start
#   lab/run_lab.sh status
#   lab/run_lab.sh logs
#   lab/run_lab.sh stop
#
# Para exponerlo a la LAN y probar GLEP desde otra máquina:
#   LAB_BIND=0.0.0.0 lab/run_lab.sh start
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/lab/docker-compose.yml")

start() {
  local http_port="${HTTP_PORT:-18080}"
  local ssh_port="${SSH_PORT:-12222}"
  local redis_port="${REDIS_PORT:-16379}"

  "${COMPOSE[@]}" up -d --build
  echo "esperando healthcheck..."
  for _ in $(seq 1 30); do
    status="$(docker inspect -f '{{.State.Health.Status}}' glep-lab-target 2>/dev/null || echo missing)"
    if [[ "$status" == "healthy" ]]; then
      break
    fi
    sleep 1
  done
  if [[ "${status:-missing}" != "healthy" ]]; then
    echo "el target no quedó healthy (estado: ${status:-missing})" >&2
    "${COMPOSE[@]}" logs --tail 40 >&2 || true
    exit 1
  fi
  echo "lab listo."
  if [[ "${LAB_BIND:-127.0.0.1}" == "0.0.0.0" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "  target LAN: ${ip:-<ip-de-esta-maquina>}  puertos: ${http_port} ${ssh_port} ${redis_port}"
    echo "  (requiere: glep --target $ip --authorized)"
  else
    echo "  target local: 127.0.0.1  puertos: ${http_port} ${ssh_port} ${redis_port}"
  fi
}

stop() {
  "${COMPOSE[@]}" down --remove-orphans
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) "${COMPOSE[@]}" ps ;;
  logs) "${COMPOSE[@]}" logs --tail 80 ;;
  *)
    echo "uso: $0 {start|stop|status|logs}" >&2
    exit 2
    ;;
esac
