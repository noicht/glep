"""Target vulnerable y descartable para probar GLEP en red.

Expone tres servicios en un contenedor aislado:
- 18080/tcp HTTP con una SQLi error-based obvia, un form de login,
  directory listing simulado, backup.zip y .git/config expuesto.
- 12222/tcp banner SSH falso.
- 16379/tcp Redis falso que responde PING/INFO.

No tiene datos reales ni acceso al host. Es un blanco de práctica.
"""

import os
import signal
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HTTP_PORT = int(os.environ.get("HTTP_PORT", "18080"))
SSH_PORT = int(os.environ.get("SSH_PORT", "12222"))
REDIS_PORT = int(os.environ.get("REDIS_PORT", "16379"))

HOME_HTML = """<!doctype html>
<html><head><title>GLEP Lab Store</title></head>
<body>
<h1>GLEP Lab Store</h1>
<p>Target de práctica. No contiene datos reales.</p>
<ul>
  <li><a href="/product?id=1">Product 1</a></li>
  <li><a href="/product?id=2">Product 2</a></li>
  <li><a href="/search?q=widget">Search</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/admin">Admin</a></li>
</ul>
<!-- TODO: remove backup.zip before prod -->
</body></html>"""

PRODUCT_HTML = """<!doctype html>
<html><head><title>Product {id}</title></head>
<body><h1>Product {id}</h1><p>Widget number {id}.</p>
<a href="/">back</a></body></html>"""

LOGIN_HTML = """<!doctype html>
<html><head><title>Login</title></head>
<body><h1>Login</h1>
<form action="/login" method="POST">
  <input name="username" type="text">
  <input name="password" type="password">
  <button type="submit">Sign in</button>
</form></body></html>"""

SQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near '%s' at line 1"
)


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):  # silenciar el access log
        pass

    def _send(self, status: int, body: str | bytes, content_type: str = "text/html") -> None:
        data = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)

        if parts.path == "/":
            return self._send(200, HOME_HTML)
        if parts.path == "/product":
            product_id = (query.get("id") or ["1"])[0]
            if self._is_sqli(product_id):
                return self._send(500, f"<html><body><h1>500</h1><p>{SQL_ERROR % product_id}</p></body></html>")
            return self._send(200, PRODUCT_HTML.format(id=product_id))
        if parts.path == "/search":
            term = (query.get("q") or [""])[0]
            # Reflejado sin escapar a propósito (XSS de laboratorio).
            return self._send(200, f"<html><head><title>Search</title></head><body><h1>Results for {term}</h1></body></html>")
        if parts.path == "/login":
            return self._send(200, LOGIN_HTML)
        if parts.path == "/admin":
            return self._send(401, "<html><body><h1>401 Unauthorized</h1></body></html>")
        if parts.path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n", "text/plain")
        if parts.path == "/backup.zip":
            return self._send(200, b"PK\x03\x04glep-lab-fake-backup", "application/zip")
        if parts.path == "/.git/config":
            return self._send(
                200,
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                "[remote \"origin\"]\n\turl = https://example.invalid/lab.git\n",
                "text/plain",
            )
        if parts.path == "/server-status":
            return self._send(200, "<html><body>Apache Server Status</body></html>")
        return self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(min(length, 65536)).decode("utf-8", errors="replace")
        parts = urlsplit(self.path)
        if parts.path == "/login":
            form = parse_qs(raw, keep_blank_values=True)
            username = (form.get("username") or [""])[0]
            if self._is_sqli(username):
                return self._send(500, f"<html><body><h1>500</h1><p>{SQL_ERROR % username}</p></body></html>")
            return self._send(200, "<html><body><h1>Invalid credentials</h1></body></html>")
        return self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")

    @staticmethod
    def _is_sqli(value: str) -> bool:
        lowered = value.lower()
        return any(
            marker in lowered
            for marker in ("'", '"', "union", "select", "sleep(", " or 1=1", "--")
        )


def serve_http() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


def _serve_banner(port: int, banner: bytes, handler) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(32)
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handler, args=(conn, banner), daemon=True).start()


def ssh_handler(conn: socket.socket, banner: bytes) -> None:
    with conn:
        try:
            conn.settimeout(3)
            conn.sendall(banner)
            conn.recv(1024)
            conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
            time.sleep(0.2)
        except OSError:
            pass


def redis_handler(conn: socket.socket, banner: bytes) -> None:
    with conn:
        try:
            conn.settimeout(3)
            data = conn.recv(4096)
            if b"PING" in data.upper():
                conn.sendall(b"+PONG\r\n")
            elif b"INFO" in data.upper():
                info = (
                    "# Server\r\nredis_version:5.0.7\r\n"
                    "# Clients\r\nconnected_clients:1\r\n"
                ).encode()
                conn.sendall(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
            elif b"COMMAND" in data.upper():
                conn.sendall(b"*0\r\n")
            else:
                conn.sendall(b"-ERR unknown command\r\n")
        except OSError:
            pass


def main() -> None:
    threading.Thread(target=serve_http, daemon=True).start()
    threading.Thread(
        target=_serve_banner,
        args=(SSH_PORT, b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n", ssh_handler),
        daemon=True,
    ).start()
    threading.Thread(
        target=_serve_banner,
        args=(REDIS_PORT, b"", redis_handler),
        daemon=True,
    ).start()

    print(
        f"glep-lab target listening: http={HTTP_PORT} ssh={SSH_PORT} redis={REDIS_PORT}",
        flush=True,
    )

    def shutdown(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
