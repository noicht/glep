"""curl como sonda HTTP del agente.

No es un crawler completo: hace un GET/POST, extrae links y formularios
básicos para que la policy tenga a dónde apuntar, y detecta errores SQL
clásicos cuando se le pide una sonda (`probe=sqli`). La detección es
conservadora: un match es un *candidate*, no una confirmación.
"""

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from glep.tools.base import Tool, ToolResult, validate_host, validate_url

_USER_AGENT = "glep/0.2 (+authorized-pentest)"

_SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning\s*:\s*mysqli?_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sqlstate\[[0-9a-z]+\]", re.I),
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"pg_query\(\)|postgresql.*error", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"sqlite.*error", re.I),
    re.compile(r"mysql_fetch_(?:array|assoc|row)", re.I),
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})", re.M)
_HEADER_RE = re.compile(r"^([A-Za-z0-9\-]+):\s*(.*)$")


class _HTMLCollector(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()

        if tag in {"a", "area"}:
            self._add_link(attrs_dict.get("href", ""))
        elif tag in {"link", "script", "img", "iframe", "source"}:
            self._add_link(attrs_dict.get("src", "") or attrs_dict.get("href", ""))

        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "") or self.base_url),
                "method": (attrs_dict.get("method", "GET") or "GET").upper(),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = attrs_dict.get("name", "")
            if name and name not in self._current_form["inputs"]:
                self._current_form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def close(self) -> None:
        super().close()
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def _add_link(self, href: str) -> None:
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            return
        absolute = urljoin(self.base_url, href)
        if absolute.startswith(("http://", "https://")) and absolute not in self.links:
            self.links.append(absolute)


class CurlTool(Tool):
    name = "curl"
    binary = "curl"
    # url O host son necesarios; se validan en build_command.
    requires_args: tuple[str, ...] = ()

    def validate_args(self, args: dict) -> str | None:
        if not isinstance(args, dict):
            return "args debe ser un objeto/dict"
        if not args.get("url") and not args.get("host"):
            return "falta arg requerido: url o host"
        return None

    def build_command(self, args: dict) -> list[str]:
        url = self._build_url(args)
        timeout = max(1, min(int(args.get("max_time", 15)), 120))

        command = [
            "curl",
            "-sS",                 # silencioso pero muestra errores
            "-i",                  # headers + body en stdout
            # No seguimos redirects automáticamente: un 302 a otro host
            # sacaría al agente del scope autorizado. La política puede
            # pedir explícitamente la URL del Location si es del target.
            "--max-redirs",
            "0",
            "--proto",
            "=http,https",
            "--max-time",
            str(timeout),
            "--connect-timeout",
            "5",
            "-A",
            _USER_AGENT,
            url,
        ]

        data = args.get("data")
        if isinstance(data, dict) and data:
            command[1:1] = ["-d", urlencode({k: str(v) for k, v in data.items()})]
        if args.get("insecure"):
            command.insert(1, "-k")

        return command

    def _build_url(self, args: dict) -> str:
        if args.get("url"):
            return validate_url(args["url"])

        host = validate_host(args["host"])
        port = int(args.get("port", 80))
        if not 1 <= port <= 65535:
            raise ValueError(f"puerto inválido: {port}")
        scheme = args.get("scheme", "https" if port == 443 else "http")
        if scheme not in ("http", "https"):
            raise ValueError(f"scheme inválido: {scheme}")
        path = str(args.get("path", "/"))
        if not path.startswith("/"):
            path = "/" + path
        return validate_url(f"{scheme}://{host}:{port}{path}")

    def parse(self, result: ToolResult) -> dict:
        status, headers, body = self._split_response(result.stdout)

        # La URL efectiva está en args, no en stdout. Si por algún motivo
        # falta, tratamos de reconstruirla desde el header Host.
        base_url = str(result.args.get("url") or "")
        if not base_url and result.args.get("host"):
            try:
                base_url = self._build_url(result.args)
            except (KeyError, ValueError):
                base_url = ""
        if not base_url:
            host = headers.get("host", "")
            base_url = f"http://{host}/" if host else ""

        collector = _HTMLCollector(base_url or "http://localhost/")
        if body:
            try:
                collector.feed(body)
                collector.close()
            except Exception:
                pass

        findings: list[dict] = []
        snippet = body.lower()

        probe = str(result.args.get("probe", ""))
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                line_start = max(0, body.rfind("\n", 0, match.start()) + 1)
                line_end = body.find("\n", match.end())
                evidence = body[line_start : line_end if line_end != -1 else match.end() + 120]
                findings.append(
                    {
                        "type": "sql_injection_candidate",
                        "severity": "high",
                        "url": base_url,
                        "evidence": evidence.strip()[:300],
                        "source": "curl",
                        "confidence": "medium",
                    }
                )
                break

        if "index of /" in snippet and not findings:
            findings.append(
                {
                    "type": "directory_listing",
                    "severity": "medium",
                    "url": base_url,
                    "evidence": "Directory listing habilitado",
                    "source": "curl",
                }
            )

        server = headers.get("server", "")
        # Solo reportamos el banner en el request principal, no en cada
        # sonda: si no, un scan de 20 URLs genera 20 findings idénticos.
        if server and not probe and re.search(r"[A-Za-z][A-Za-z0-9_.-]*/\d", server):
            findings.append(
                {
                    "type": "server_version_disclosure",
                    "severity": "low",
                    "url": base_url,
                    "evidence": f"Server: {server}",
                    "source": "curl",
                }
            )

        title_match = _TITLE_RE.search(body)
        http_info = {
            "url": base_url,
            "status": status,
            "server": server,
            "title": title_match.group(1).strip()[:120] if title_match else "",
            "content_length": len(body),
            "probe": probe,
        }

        errors = []
        if result.returncode != 0:
            errors.append(f"curl {base_url}: {result.stderr.strip() or result.returncode}")

        return {
            "findings": findings,
            "urls": ([base_url] if base_url else []) + collector.links,
            "forms": collector.forms,
            "http": http_info,
            "errors": errors,
        }

    @staticmethod
    def _split_response(stdout: str) -> tuple[int | None, dict[str, str], str]:
        if not stdout:
            return None, {}, ""

        separator = "\r\n\r\n" if "\r\n\r\n" in stdout else "\n\n"
        if separator in stdout:
            head, body = stdout.split(separator, 1)
        else:
            head, body = stdout, ""

        # Con -L puede haber varios bloques de headers. Parseamos el último.
        status_matches = list(_STATUS_RE.finditer(head))
        status = int(status_matches[-1].group(1)) if status_matches else None
        last_header_block = head[status_matches[-1].end() :] if status_matches else head

        headers: dict[str, str] = {}
        for line in last_header_block.splitlines():
            match = _HEADER_RE.match(line.strip())
            if match:
                headers[match.group(1).lower()] = match.group(2).strip()

        return status, headers, body


def sqli_probe_url(url: str, payload: str = "1'") -> str | None:
    """Devuelve la URL con cada parámetro de query mutado al payload.

    Es una sonda de error-based SQLi: no intenta bypass, solo provocar un
    error que delate concatenación insegura. Si la URL no tiene query,
    devuelve None.
    """
    parts = urlsplit(url)
    if not parts.query:
        return None
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return None
    mutated = [
        (key, f"{value}'" if value else payload) for key, value in pairs
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(mutated), "")
    )
