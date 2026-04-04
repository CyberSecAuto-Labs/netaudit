"""Integration test target — performs known network operations for end-to-end testing.

Run directly as a script; strace captures the connect() syscalls it generates:
  - Loopback TCP (local HTTP server on 127.0.0.1)
  - Unix domain socket
  - AF_NETLINK via socket.getaddrinfo (glibc resolver)
  - External TCP to 198.51.100.1:443 (TEST-NET-2 — won't route, no flaky deps)
"""

from __future__ import annotations

import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _SilentHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def _loopback_tcp() -> None:
    """Connect to a local HTTP server on 127.0.0.1."""
    server = HTTPServer(("127.0.0.1", 0), _SilentHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.handle_request, daemon=True)
    t.start()
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        s.recv(1024)
    t.join(timeout=2)
    server.server_close()


def _unix_socket() -> None:
    """Connect to a Unix domain socket."""
    with tempfile.TemporaryDirectory() as tmp:
        sock_path = tmp + "/test.sock"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        cli.connect(sock_path)
        conn, _ = srv.accept()
        conn.close()
        cli.close()
        srv.close()


def _dns_netlink() -> None:
    """Trigger AF_NETLINK via glibc resolver."""
    try:
        socket.getaddrinfo("localhost", 80)
    except socket.gaierror:
        pass


def _external_connect() -> None:
    """Non-blocking connect to TEST-NET-2 (198.51.100.1:443) — expected violation."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect(("198.51.100.1", 443))
    except (BlockingIOError, OSError):
        pass
    finally:
        s.close()


def main() -> None:
    _loopback_tcp()
    _unix_socket()
    _dns_netlink()
    _external_connect()


if __name__ == "__main__":
    main()
