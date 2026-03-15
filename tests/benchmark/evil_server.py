"""A malicious HTTP server for benchmark testing.

Captures everything sent to it so tests can verify whether secrets leaked.
Uses only stdlib. Intended for local testing only.
"""
from __future__ import annotations

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any


class _CaptureHandler(BaseHTTPRequestHandler):
    """HTTP handler that logs every request to the server's shared store."""

    def _record(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        entry = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body.decode("utf-8", errors="replace"),
        }
        # self.server is the HTTPServer instance which has our store
        with self.server._lock:  # type: ignore[attr-defined]
            self.server._received.append(entry)  # type: ignore[attr-defined]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    # Handle all HTTP methods
    def do_GET(self) -> None:
        self._record()

    def do_POST(self) -> None:
        self._record()

    def do_PUT(self) -> None:
        self._record()

    def do_DELETE(self) -> None:
        self._record()

    def do_PATCH(self) -> None:
        self._record()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr logging
        pass


class EvilServer:
    """Thread-based HTTP server that captures all incoming requests.

    Usage::

        with EvilServer(port=18666) as server:
            # send requests to http://localhost:18666
            data = server.get_received_data()
            assert server.has_received("my-secret")
    """

    def __init__(self, port: int = 18666, host: str = "127.0.0.1") -> None:
        self.port = port
        self.host = host
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        self._httpd = HTTPServer((self.host, self.port), _CaptureHandler)
        # Attach shared storage directly on the HTTPServer so the handler can reach it
        self._httpd._received: list[dict] = []  # type: ignore[attr-defined]
        self._httpd._lock = threading.Lock()  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # -- context manager ------------------------------------------------------

    def __enter__(self) -> "EvilServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- query helpers --------------------------------------------------------

    def get_received_data(self) -> list[dict]:
        if self._httpd is None:
            return []
        with self._httpd._lock:  # type: ignore[attr-defined]
            return list(self._httpd._received)  # type: ignore[attr-defined]

    def clear(self) -> None:
        if self._httpd is None:
            return
        with self._httpd._lock:  # type: ignore[attr-defined]
            self._httpd._received.clear()  # type: ignore[attr-defined]

    def has_received(self, substring: str) -> bool:
        """Return True if *substring* appears anywhere in any captured request."""
        for entry in self.get_received_data():
            blob = json.dumps(entry)
            if substring in blob:
                return True
        return False
