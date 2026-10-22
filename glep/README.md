# GLEP — GBNF LLM Edge Pentester

Agente de pentesting silencioso pensado para correr en un Raspberry Pi Zero 2W
(512 MB RAM, sin GPU) o en cualquier Linux con Python. Sin chat ni razonamiento
libre: un loop ReAct (`observar → decidir → ejecutar → repetir`) que dispara
herramientas reales (`nmap`, `nikto`, `hydra`, `sqlmap`, `curl`, `dig`) contra
un objetivo autorizado, acumula observaciones y escribe un reporte JSON +
Markdown.

> **Estado:** v0.2.0. El pipeline funciona end-to-end contra el lab incluido.
> El modo determinístico es el default y el recomendado para la Pi. El modo
> LLM es experimental.

> **Aviso legal:** GLEP ejecuta herramientas ofensivas reales. Usalo solo
> contra sistemas que te pertenecen o para los que tenés autorización escrita.
> El chequeo de alcance es una ayuda, no una garantía legal.

---

## Índice

1. [Qué cambió en v0.2](#qué-cambió-en-v020)
2. [Requisitos e instalación](#requisitos-e-instalación)
3. [Quick start](#quick-start)
4. [Configuración completa](#configuración-completa)
5. [CLI](#cli)
6. [Cómo funciona](#cómo-funciona)
7. [Lab de pruebas](#lab-de-pruebas)
8. [Tests y benchmarks](#tests-y-benchmarks)
9. [Troubleshooting](#troubleshooting)
10. [Seguridad, alcance y limitaciones](#seguridad-alcance-y-limitaciones)

---

## Qué cambió en v0.2

La v0.1 era un esqueleto: el loop existía, pero los parsers de las tools
devolvían estructuras vacías, así que el agente nunca veía un puerto abierto ni
un finding. La v0.2 convierte eso en un pipeline usable y testeable.

### Pipeline real

| Área | Antes (v0.1) | Ahora (v0.2) |
|---|---|---|
| nmap | `parse()` devolvía `{"open_ports": [], "services": {}}` | corre `-sV` con salida XML y parsea puerto, servicio, producto y versión |
| curl | solo devolvía `raw_response` | parsea status, headers, título, links y forms; detecta errores SQL y directory listing |
| nikto | `findings: []` | parsea las líneas `+ ...` y clasifica severidad |
| hydra | `findings: []` | parsea `[puerto][servicio] host: ... login: ... password: ...` |
| sqlmap | `findings: []` | detecta confirmación de SQLi, parámetro y DBMS |
| dig | solo `dns_records` | valida record type, timeouts y errores de resolución |
| Estado | puertos/findings manuales | `EngagementState` acumula puertos, servicios, URLs, forms, findings, DNS y errores, con deduplicación |
| Reporte | no existía | JSON + Markdown en `reports/` |
| Scope | no existía | loopback/LAN/público con autorización explícita |

### Robustez y seguridad

- **Validación de argumentos** antes de cada `subprocess`: host, puerto, rango
  y URL. Nunca se usa `shell=True` ni concatenación de strings.
- **Binarios opcionales**: si falta `nikto`, `sqlmap` o `hydra`, la acción se
  registra como `skipped` y el engagement sigue; no se cuelga ni explota.
- **Timeouts** por tool y por decisión LLM.
- **Scope guard** (`src/glep/scope.py`): resuelve el host y clasifica
  loopback / privado / público. LAN requiere `--authorized`; público requiere
  además `target.allow_public: true`.
- **Sin redirects cross-host**: `curl` no sigue redirects automáticamente para
  no salir del alcance autorizado.
- **Gates de explotación**: `sqlmap` solo con `allow_exploit: true`; `hydra`
  solo con `allow_bruteforce: true`. El loop aplica los gates incluso si la
  policy LLM intenta elegir esas tools.
- **sqlmap no explota**: corre con `--level=1 --risk=1` (detección).
- **hydra conservador**: `-t 4 -f`, para no tumbar cuentas/servicios.

### LLM más usable en poca RAM

- Prompt compacto: paths en vez de URLs completas, resumen de servicios y
  últimos findings. `n_ctx=512` deja de desbordarse enseguida.
- **Gramática GBNF por fase**, generada solo con las tools válidas *y con
  binario instalado*. Si nikto no está, el modelo no puede elegir nikto.
- **Ejemplos concretos con el target real**: un modelo de 0.5B copia el
  ejemplo; los placeholders tipo `<target>` terminaban en la acción.
- Validación de host/URL contra el objetivo: el modelo no puede pivotear a
  `example.com` ni a otra IP.
- Rechazo de acciones ya ejecutadas.
- **Circuit breaker**: tras 2 fallos seguidos (timeout, JSON inválido o acción
  inválida) se apaga el LLM y sigue `DeterministicPolicy` durante el resto del
  engagement.

### Lab, tests y tooling

- `lab/`: target Docker aislado con HTTP vulnerable, SSH falso y Redis falso.
- `scripts/smoke_test.sh`: test end-to-end que levanta el lab, corre GLEP y
  valida el JSON del reporte.
- `scripts/bench_llm.py`: mide carga, RSS y latencia de decisión en la Pi.
- `Makefile` con atajos (`make test`, `make lab-up`, `make smoke`, etc.).
- `31` tests de parsers, loop, scope, estado, reporte y validación LLM.
- Versión `0.1.0 → 0.2.0`.

---

## Requisitos e instalación

### Sistema

- Linux (probado en Debian/Ubuntu x86_64).
- Python **>= 3.10**.
- Docker + Docker Compose v2 para el lab (opcional si solo querés usar el
  agente contra otro target).
- Para la Pi Zero 2W: Raspberry Pi OS de 64 bits; el modelo GGUF no entra
  cómodo en 32 bits ni en 512 MB con LLM.

### Python

```bash
cd /ruta/a/glep
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Si no querés el modo LLM ni tests:

```bash
.venv/bin/pip install -e .
```

Dependencias:

- `PyYAML>=6.0` (siempre).
- `llama-cpp-python>=0.2.90` (solo modo LLM, extra `[llm]`).
- `pytest>=8.0` (solo desarrollo, extra `[dev]`).

### Herramientas externas

| Tool | Paquete Debian/Ubuntu | Obligatoria |
|---|---|---|
| nmap | `nmap` | sí para RECON |
| curl | `curl` | sí para VULN_SCAN web |
| dig | `dnsutils` | recomendada |
| nikto | `nikto` | opcional |
| sqlmap | `sqlmap` | opcional (confirmar SQLi) |
| hydra | `hydra` | opcional (fuerza bruta) |

```bash
sudo apt update
sudo apt install nmap curl dnsutils nikto sqlmap hydra
```

### Verificación

```bash
.venv/bin/glep --version
.venv/bin/glep --list-tools
.venv/bin/glep --check
```

Ejemplo de salida de `--check`:

```text
GLEP 0.2.0
target: 127.0.0.1  puertos: 1-1024
scope: loopback ['127.0.0.1'] -> OK
       loopback: tu propia máquina, permitido
policy: deterministic
tools:
  nmap     ok     (nmap)
  nikto    FALTA  (nikto)
  hydra    FALTA  (hydra)
  sqlmap   FALTA  (sqlmap)
  curl     ok     (curl)
  dig      ok     (dig)
log: /ruta/a/glep/logs/glep.log
reports: /ruta/a/glep/reports
```

---

## Quick start

### Lab local (recomendado para la primera prueba)

```bash
# 1. dependencias
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

# 2. levantar el target vulnerable en 127.0.0.1:18080/12222/16379
./lab/run_lab.sh start

# 3. correr el agente contra el lab
.venv/bin/glep --config config/settings.lab.yaml

# 4. leer el reporte
ls -t reports/*.md | head -1
```

Todo junto y con validación automática:

```bash
./scripts/smoke_test.sh
```

### Target propio en la LAN

```bash
.venv/bin/glep \
  --config config/settings.yaml \
  --target 192.168.1.50 \
  --authorized
```

`--authorized` confirma que el equipo es tuyo o tenés permiso. Sin ese flag,
el agente se niega a tocar cualquier target que no sea loopback.

### Target público

Solo con autorización explícita. Hay que habilitar dos cosas:

1. `--authorized` en la CLI.
2. `target.allow_public: true` en la config.

```bash
.venv/bin/glep \
  --config config/settings.yaml \
  --target 203.0.113.10 \
  --authorized
```

Con `allow_public: false` (default), el agente rechaza el target aunque pases
`--authorized`.

---

## Configuración completa

### Dónde vive la config y precedencia

- Config por defecto: `config/settings.yaml`.
- Config del lab: `config/settings.lab.yaml`.
- Se puede pasar otra con `--config /ruta/archivo.yaml`.

Las rutas relativas dentro del YAML (`model_path`, `grammar_path`,
`logging.file`, `report.dir`, wordlists) se resuelven contra la **raíz del
proyecto**, no contra el cwd. La raíz se detecta como el padre del directorio
`config/`; si el archivo está en otro lado, se usa su propio directorio.

Precedencia en GLEP:

```text
flags de CLI  >  archivo YAML  >  defaults del código
```

Las variables de entorno (`LAB_BIND`, `HTTP_PORT`, etc.) solo afectan al
contenedor del lab, no a la config de GLEP. Si cambiás los puertos del lab,
tenés que reflejarlos en `target.port_range`/`target.web_ports`.

### `settings.yaml` comentado

Esta es la config completa con todos los campos que lee el código:

```yaml
policy:
  # "deterministic" | "llm"
  mode: deterministic
  # Solo aplica si LLMPolicy no se puede inicializar (modelo/grammar rotos).
  # Los fallos en runtime siempre caen a determinístico (circuit breaker).
  fallback_to_deterministic: true
  # Permite sqlmap en EXPLOIT_ATTEMPT (detección, no dump).
  allow_exploit: true
  # Permite hydra en EXPLOIT_ATTEMPT. Default false a propósito.
  allow_bruteforce: false
  # Tope de URLs con query params a sondear por SQLi con curl.
  max_http_probes: 20

llm:
  # Ruta al GGUF. Relativa a la raíz del proyecto o absoluta.
  model_path: ./models/Qwen2.5-0.5B-Instruct-Q3_K_M.gguf
  # Gramática GBNF base. La policy la adapta por fase.
  grammar_path: grammar/tool_call.gbnf
  # Context window. 512 es el default pensado para la Pi.
  n_ctx: 512
  # Threads de llama.cpp. En la Pi Zero 2W: 2-4.
  n_threads: 4
  # Timeout por decisión LLM (un signal.alarm).
  timeout_seconds: 15

target:
  # IP o hostname. También se puede pisar con --target.
  host: 127.0.0.1
  # Sintaxis nmap: "1-1024", "22,80,443", "1-65535".
  port_range: "1-1024"
  # Puertos que se tratan como web aunque nmap no detecte el servicio.
  # Ejemplo lab: [18080]
  web_ports: []
  # Equivalente a --authorized para targets privados/LAN.
  authorized: false
  # Segundo candado para targets públicos. Default false.
  allow_public: false

tools:
  # Timeout por ejecución de tool. También se puede pisar con --timeout.
  timeout_seconds: 120
  wordlists:
    # Solo se usan si allow_bruteforce: true.
    users: /opt/glep/wordlists/users.txt
    passwords: /opt/glep/wordlists/passwords.txt

loop:
  # Tope duro de acciones. También se puede pisar con --max-iterations.
  max_iterations: 200

report:
  # Directorio de salida. También se puede pisar con --report-dir.
  dir: ./reports

logging:
  # Archivo de log. Si lo seteás a vacío/null, loguea a stderr.
  # Si omitís la clave, usa ./logs/glep.log.
  file: ./logs/glep.log
  # DEBUG | INFO | WARNING | ERROR
  level: INFO
```

### Referencia de claves

#### `policy`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `mode` | `deterministic` \| `llm` | `deterministic` | Quién elige la próxima acción |
| `fallback_to_deterministic` | bool | `true` | Si `LLMPolicy` falla al inicializar, usa determinística en vez de abortar |
| `allow_exploit` | bool | `true` | Habilita `sqlmap` en EXPLOIT_ATTEMPT |
| `allow_bruteforce` | bool | `false` | Habilita `hydra` en EXPLOIT_ATTEMPT |
| `max_http_probes` | int | `20` | Tope de URLs con query a sondear por SQLi |

Los gates `allow_exploit` y `allow_bruteforce` se aplican en **dos capas**:
`DeterministicPolicy` no las elige y `ReactLoop` las bloquea aunque otra policy
las proponga. También se filtran de la gramática/tools del LLM.

#### `llm`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `model_path` | path | — | GGUF de Qwen2.5-0.5B-Instruct Q3_K_M |
| `grammar_path` | path | `grammar/tool_call.gbnf` | Gramática base de tool calls |
| `n_ctx` | int | `512` | Context window de llama.cpp |
| `n_threads` | int | `4` | Threads de inferencia |
| `timeout_seconds` | int | `15` | Timeout por decisión |

El modelo **no** se descarga solo: tiene que existir en `model_path`. Si no
existe y `fallback_to_deterministic: true`, GLEP arranca igual en modo
determinístico y lo deja en el log.

#### `target`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `host` | str | `127.0.0.1` | IP/hostname objetivo |
| `port_range` | str | `1-1024` | Rango/puertos para nmap |
| `web_ports` | list[int] | `[]` | Puertos forzados como web aunque nmap no los detecte |
| `authorized` | bool | `false` | Equivale a `--authorized` |
| `allow_public` | bool | `false` | Permite targets públicos (junto con autorización) |

`web_ports` es útil si el target está detrás de un proxy o nmap no identifica
el servicio. Esos puertos se prueban con `curl`/`nikto` aunque nmap no marque
`http`.

#### `tools`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `timeout_seconds` | int | `120` | Timeout por ejecución de tool |
| `wordlists.users` | path | `/opt/glep/wordlists/users.txt` | Lista de usuarios para hydra |
| `wordlists.passwords` | path | `/opt/glep/wordlists/passwords.txt` | Lista de passwords para hydra |

Los wordlists se validan antes de correr hydra. Si no existen, la tool
devuelve error y el loop sigue.

#### `loop`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `max_iterations` | int | `200` | Tope de acciones antes de abortar con warning |

#### `report`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `dir` | path | `./reports` | Directorio de salida JSON/Markdown |

Archivos generados:

```text
reports/glep-<host>-<YYYYMMDDTHHMMSSZ>.json
reports/glep-<host>-<YYYYMMDDTHHMMSSZ>.md
```

#### `logging`

| Clave | Tipo | Default | Qué hace |
|---|---|---|---|
| `file` | path \| null | `./logs/glep.log` | Archivo de log; si está vacío, va a stderr |
| `level` | str | `INFO` | Nivel de logging |

`--verbose` agrega salida a stderr además del archivo. `--quiet` silencia el
resumen final por stdout.

### Ejemplos de configuración por escenario

#### Lab local (loopback)

`config/settings.lab.yaml` ya viene listo:

```yaml
policy:
  mode: deterministic
  allow_exploit: true
  allow_bruteforce: false

target:
  host: 127.0.0.1
  port_range: "12000-19999"
  web_ports: [18080]
  authorized: false
  allow_public: false

tools:
  timeout_seconds: 120
  wordlists:
    users: ./lab/wordlists/users.txt
    passwords: ./lab/wordlists/passwords.txt

report:
  dir: ./reports
logging:
  file: ./logs/glep-lab.log
```

#### LAN, equipo propio

```yaml
target:
  host: 192.168.1.50
  port_range: "1-10000"
  authorized: true       # o pasar --authorized
  allow_public: false
```

#### Target público autorizado

```yaml
target:
  host: 203.0.113.10
  port_range: "1-1024"
  authorized: true
  allow_public: true     # segundo candado obligatorio
```

#### Modo seguro (sin explotación ni fuerza bruta)

```yaml
policy:
  mode: deterministic
  allow_exploit: false
  allow_bruteforce: false
```

El agente hace RECON + VULN_SCAN y salta EXPLOIT_ATTEMPT. Sirve para
inventario y validación no invasiva.

#### Modo LLM en la Pi

```yaml
policy:
  mode: llm
  fallback_to_deterministic: true
  allow_exploit: true
  allow_bruteforce: false

llm:
  model_path: ./models/Qwen2.5-0.5B-Instruct-Q3_K_M.gguf
  grammar_path: grammar/tool_call.gbnf
  n_ctx: 512
  n_threads: 2
  timeout_seconds: 20
```

Antes de dejarlo fijo, medí RAM/latencia:

```bash
.venv/bin/python scripts/bench_llm.py --n-ctx 512 --threads 2 --runs 3
```

#### Scan más rápido / más profundo

Rápido (solo puertos conocidos):

```yaml
target:
  port_range: "22,80,443,3000,5000,8000,8080,8443"
```

Profundo (más lento y más ruidoso):

```yaml
target:
  port_range: "1-65535"
policy:
  max_http_probes: 50
tools:
  timeout_seconds: 300
```

### Variables de entorno del lab

| Variable | Default | Qué hace |
|---|---|---|
| `LAB_BIND` | `127.0.0.1` | Interfaz donde Docker publica los puertos del lab |
| `HTTP_PORT` | `18080` | Puerto HTTP del contenedor |
| `SSH_PORT` | `12222` | Puerto SSH falso del contenedor |
| `REDIS_PORT` | `16379` | Puerto Redis falso del contenedor |

Ejemplo:

```bash
LAB_BIND=0.0.0.0 ./lab/run_lab.sh start
```

Los tres puertos se interpolan en `docker-compose.yml` y también se publican
con el mismo valor. Si los cambiás, actualizá `target.port_range` y
`target.web_ports` en la config de GLEP:

```bash
HTTP_PORT=9000 SSH_PORT=9022 REDIS_PORT=9637 ./lab/run_lab.sh start
# target.port_range: "9000-9637"
# target.web_ports: [9000]
```

---

## CLI

```text
glep [--config PATH] [--target HOST] [--port-range RANGE] [--policy MODE]
     [--authorized] [--check] [--list-tools] [--report-dir DIR] [--no-report]
     [--log-file PATH] [--max-iterations N] [--timeout S] [--verbose] [--quiet]
```

| Flag | Qué hace |
|---|---|
| `--config PATH` | Config YAML (default `config/settings.yaml`) |
| `--version` | Muestra la versión |
| `--target HOST` | Pisa `target.host` |
| `--port-range RANGE` | Pisa `target.port_range` |
| `--policy deterministic\|llm` | Pisa `policy.mode` |
| `--authorized` | Confirma autorización para LAN/público |
| `--check` | Preflight: scope, tools, log y report dir; no escanea |
| `--list-tools` | Lista tools y si el binario está instalado |
| `--report-dir DIR` | Pisa `report.dir` |
| `--no-report` | No escribe JSON/Markdown |
| `--log-file PATH` | Pisa `logging.file` |
| `--max-iterations N` | Pisa `loop.max_iterations` |
| `--timeout S` | Pisa `tools.timeout_seconds` |
| `--verbose` | Copia el log a stderr |
| `--quiet` | No imprime el resumen final |

Ejemplos:

```bash
# ver qué hay instalado y si el target está permitido
.venv/bin/glep --config config/settings.lab.yaml --check

# correr el lab con la config por defecto
.venv/bin/glep --config config/settings.lab.yaml

# LAN, forzando policy y límites
.venv/bin/glep --config config/settings.yaml \
  --target 192.168.1.50 --authorized \
  --policy deterministic --timeout 180 --max-iterations 100

# solo herramientas
.venv/bin/glep --list-tools
```

---

## Cómo funciona

### Fases

La estructura es fija; lo único intercambiable es la decisión de la próxima
acción.

| Fase | Acciones | Transición |
|---|---|---|
| `RECON` | `nmap` (`-Pn -sV --version-light -p <rango> -oX -`) y `dig` | cuando la policy devuelve `None` |
| `VULN_SCAN` | `curl` a puertos web, sonda SQLi en query params, `nikto` | cuando no quedan acciones |
| `EXPLOIT_ATTEMPT` | `sqlmap` para candidatos; `hydra` si se habilita | cuando no quedan acciones |
| `REPORT` | sin tools | pasa a `DONE` |
| `DONE` | — | fin |

Flujo determinístico concreto:

1. `nmap` una vez.
2. `dig` una vez.
3. Para cada puerto web (`services` con `http`/`ssl` o `web_ports`):
   `curl` a la raíz.
4. Para cada URL descubierta con query params, hasta `max_http_probes`:
   `curl` agregando `'` a cada valor de query (o `1'` si el valor está vacío)
   para provocar un error SQL.
5. Para cada puerto web: `nikto` si está instalado.
6. Para cada finding `sql_injection_candidate`: `sqlmap` si
   `allow_exploit: true`.
7. Para cada servicio SSH/FTP/Telnet/RDP/MySQL/Postgres: `hydra` si
   `allow_bruteforce: true`.
8. Escribe reporte y termina.

### Tools y parseo

| Tool | Comando base | Parseo |
|---|---|---|
| `nmap` | `nmap -Pn -sV --version-light --host-timeout 120s -p RANGE -oX - HOST` | XML: puertos abiertos, servicio/producto/versión; fallback a texto |
| `curl` | `curl -sS -i --max-redirs 0 --proto =http,https --max-time N -A glep/0.2 URL` | status, headers, título, links, forms, errores SQL, directory listing, banner |
| `nikto` | `nikto -h URL -nointeractive -ask no -maxtime 120s -Tuning 123b` | líneas `+ ...` clasificadas |
| `sqlmap` | `sqlmap -u URL --batch --level=1 --risk=1 --threads=1 ...` | confirmación, parámetro, DBMS |
| `hydra` | `hydra -L users -P passwords -t 4 -f -I servicio://host:puerto` | credenciales válidas |
| `dig` | `dig HOST TYPE +short +time=3 +tries=1` | registros DNS |

`curl` **no** sigue redirects (`--max-redirs 0`): un 302 a otro host saldría
del scope. Si el `Location` es del mismo target, se puede pedir a mano.

### Scope y autorización

`scope.py` resuelve el host y clasifica cada dirección:

| Target | Requisito | Resultado |
|---|---|---|
| Loopback (`127.0.0.0/8`, `::1`) | ninguno | permitido |
| Privado/LAN (`10/8`, `172.16/12`, `192.168/16`, link-local) | `--authorized` o `target.authorized: true` | permitido con flag |
| Público | `--authorized` **y** `target.allow_public: true` | permitido con ambos |
| Público sin `allow_public` | — | bloqueado |
| `0.0.0.0`, multicast | — | bloqueado |
| Host que no resuelve | — | error y salida `2` |

Si el target resuelve a varias IPs y alguna es pública, se trata como público.

### Reporte

Cada corrida genera:

- **JSON**: estado completo + metadata (scope, policy, versión, fecha,
  acciones, errores). Ideal para diff entre corridas.
- **Markdown**: resumen de severidades, puertos/servicios, findings,
  URLs descubiertas, acciones ejecutadas y limitaciones.

Los findings automáticos son **indicadores**, no confirmaciones. Un
`sql_injection_candidate` de `curl` requiere validación manual o `sqlmap`.
Si hydra encuentra credenciales, el reporte las incluye: tratalo como
material sensible.

### Modo LLM

`LLMPolicy` usa Qwen2.5-0.5B-Instruct Q3_K_M vía `llama-cpp-python`:

1. Construye un prompt compacto con target, fase, puertos, servicios, paths,
   findings y acciones ya hechas.
2. Genera una gramática GBNF **solo con las tools disponibles de la fase**.
3. Pide un único tool call JSON.
4. Valida fase, args, binario, host/URL y repetición.
5. Si algo falla, usa `DeterministicPolicy`. Tras 2 fallos seguidos, apaga el
   LLM para el resto del engagement.

El modelo no razona libremente: elige entre un set acotado de acciones. Aun
así, un 0.5B se equivoca seguido; el valor del modo LLM es experimental y de
benchmark, no reemplaza al determinístico.

---

## Lab de pruebas

`lab/` levanta un contenedor descartable con tres servicios:

| Puerto | Servicio | Detalle |
|---:|---|---|
| `18080/tcp` | HTTP | store falso con SQLi error-based en `/product?id=1`, form de login POST, `.git/config`, `backup.zip`, directory listing y banner Apache |
| `12222/tcp` | SSH | banner `OpenSSH 7.4p1` falso |
| `16379/tcp` | Redis | responde `PING`/`INFO` como Redis 5.0.7 |

No tiene datos reales ni acceso al host. El filesystem del contenedor es de
solo lectura, corre como usuario no privilegiado y con `no-new-privileges`.

### Local

```bash
./lab/run_lab.sh start
./lab/run_lab.sh status
./lab/run_lab.sh logs
./lab/run_lab.sh stop
```

Targets:

```text
http://127.0.0.1:18080/
ssh://127.0.0.1:12222/
redis://127.0.0.1:16379/
```

### Desde otra máquina de la LAN

```bash
LAB_BIND=0.0.0.0 ./lab/run_lab.sh start
hostname -I
```

En la otra máquina:

```bash
glep --config config/settings.lab.yaml \
     --target <IP-DEL-HOST> \
     --authorized
```

No dejes el lab expuesto a Internet. Cuando termines:

```bash
./lab/run_lab.sh stop
```

### Reiniciar de cero

```bash
./lab/run_lab.sh stop
docker image rm glep-lab-target:latest 2>/dev/null || true
./lab/run_lab.sh start
```

---

## Tests y benchmarks

### Unit tests

```bash
.venv/bin/python -m pytest
# o
make test
```

Cobertura actual: `31` tests.

- `tests/test_tools.py`: parsers nmap/curl/nikto/hydra/sqlmap/dig,
  validación de args, binario faltante.
- `tests/test_loop.py`: flujo completo con tools falsas, skip de binarios,
  orden de RECON.
- `tests/test_scope.py`: loopback/LAN/público/inválido.
- `tests/test_state.py`: deduplicación, `complete_args`, web ports, summary.
- `tests/test_report.py`: JSON + Markdown.
- `tests/test_llm_validation.py`: host/URL/fase/repetición.

### Smoke test end-to-end

```bash
./scripts/smoke_test.sh
```

Hace:

1. `lab/run_lab.sh start`.
2. `glep --check`.
3. Corre GLEP determinístico contra `127.0.0.1`.
4. Valida que el JSON tenga `18080`, `12222`, `16379`, al menos un
   `sql_injection_candidate` y fase `DONE`.
5. Muestra el reporte y baja el lab.

Resultado esperado en este entorno:

```text
OK: glep-127.0.0.1-....json
    puertos=[12222, 16379, 18080]
    findings=3 (sql_injection_candidate=2)
smoke test OK
```

### Benchmark LLM

```bash
.venv/bin/python scripts/bench_llm.py
.venv/bin/python scripts/bench_llm.py --runs 5 --n-ctx 512 --threads 2
```

Mide carga, RSS máximo y latencia por decisión. Resultado medido en x86_64
(8 cores, `n_ctx=512`, Q3_K_M):

| Métrica | Valor |
|---|---:|
| Carga del modelo | 1–8 s (según caché) |
| RSS máximo | ~740–770 MB |
| Latencia por decisión | ~8 s |
| Engagement completo (lab determinístico) | ~8–15 s |
| Engagement completo (lab LLM) | ~33–66 s |

**Pi Zero 2W:** 740–770 MB de RSS no entran en 512 MB. En ARM puede bajar,
pero el margen es chico. Medilo en la Pi antes de dejar `mode: llm` como
default. Para la Pi, hoy: `mode: deterministic`.

---

## Troubleshooting

| Síntoma | Causa probable | Solución |
|---|---|---|
| `binario no encontrado: nikto` | no está instalado | `sudo apt install nikto` o ignorarlo; el reporte lo marca |
| `target fuera de alcance` | LAN/público sin autorización | agregar `--authorized`; para público también `allow_public: true` |
| `target público bloqueado por config` | falta `allow_public` | habilitarlo solo con autorización explícita |
| `no se pudo resolver ...` | DNS/host mal escrito | usar IP o corregir el hostname |
| `Requested tokens exceed context window` | prompt > `n_ctx` | bajar estado/paths, subir `n_ctx` o usar determinístico |
| `LLM deshabilitado tras 2 fallos seguidos` | el 0.5B se equivocó/repite | es esperado; sigue determinístico |
| `hydra: wordlist no encontrada` | rutas de `tools.wordlists` mal | crear los archivos o corregir las rutas |
| `nmap` no ve puertos | target caído/firewall | verificar el target; ya se usa `-Pn` |
| `curl` no sigue un redirect | comportamiento intencional | pedir la URL del `Location` a mano si es del target |
| reporte vacío o no aparece | `--no-report` o permisos | revisar `report.dir` y permisos |
| puerto Docker ocupado | otro servicio usa 18080/12222/16379 | `./lab/run_lab.sh stop` o cambiar puertos/compose |
| contenedor no healthy | build/arranque falló | `./lab/run_lab.sh logs` |

Logs:

```bash
tail -f logs/glep.log
tail -f logs/glep-lab.log
```

---

## Seguridad, alcance y limitaciones

### Reglas de seguridad

- Solo targets autorizados. El scope guard es una ayuda, no un permiso legal.
- `--authorized` es obligatorio fuera de loopback.
- Targets públicos requieren `--authorized` **y** `allow_public: true`.
- `sqlmap` corre en modo detección (`--level=1 --risk=1`), sin dump.
- `hydra` corre con `-t 4 -f` y solo con `allow_bruteforce: true`.
- No se usa `shell=True`; host, puerto, rango, URL y wordlists se validan.
- `curl` no sigue redirects cross-host.
- No hay evasión, sigilo, persistencia ni movimiento lateral.

### Limitaciones conocidas

- Detección de SQLi **error-based y conservadora**: los candidatos requieren
  confirmación manual o `sqlmap`.
- No hay crawling profundo ni autenticación: solo links/forms de la raíz.
- No hay soporte TLS con certificados inválidos salvo `insecure` manual (el
  lab es HTTP).
- No hay `--resume`: cada corrida empieza de cero.
- El LLM de 0.5B decide mal con frecuencia; el fallback es parte del diseño.
- El reporte puede contener credenciales si hydra las encuentra.
- El lab está pensado para loopback/LAN; no lo expongas a Internet.

### Próximos pasos

1. Medir `scripts/bench_llm.py` en la Pi Zero 2W real.
2. Agregar probes XSS/reflected y paths comunes con presupuesto configurable.
3. `--resume` usando el JSON del reporte como estado.
4. Imagen ARM del lab + GLEP para pruebas de campo.
5. Parseo de `nikto` JSON si la versión instalada lo soporta.

---

## Estructura del repo

```text
config/
  settings.yaml            config default (deterministic)
  settings.lab.yaml        config del lab
grammar/
  tool_call.gbnf           gramática GBNF base
lab/
  Dockerfile               target de práctica
  docker-compose.yml
  server.py                HTTP + SSH + Redis falsos
  run_lab.sh               start/stop/status/logs
  wordlists/               users/passwords para hydra
scripts/
  smoke_test.sh            test end-to-end
  bench_llm.py             benchmark LLM
src/glep/
  main.py                  CLI, scope, preflight, reporte
  loop.py                  máquina de estados + ejecución
  state.py                 estado del engagement
  scope.py                 autorización/alcance
  report.py                JSON + Markdown
  logger.py                logging
  policy/
    base.py
    deterministic.py
    llm.py
  tools/
    base.py                validación + subprocess
    nmap_tool.py
    curl_tool.py
    nikto_tool.py
    hydra_tool.py
    sqlmap_tool.py
    dig_tool.py
tests/                     31 tests
Makefile
pyproject.toml
requirements.txt
requirements-dev.txt
README.md
```

### Makefile

```bash
make install     # venv + pip install -e '.[dev]'
make test        # pytest
make check       # glep --check
make lab-up      # levantar lab
make lab-down    # bajar lab
make lab-status
make smoke       # test end-to-end
make bench-llm
make run         # glep con config/settings.yaml
```
