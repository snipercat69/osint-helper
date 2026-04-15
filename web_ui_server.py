#!/usr/bin/env python3
"""Web UI backend for OSINT Helper.

Serves a small static frontend and exposes /api/osint for passive recon calls.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import mimetypes
import os
import traceback
import urllib.parse

import osint_helper as core

HOST = os.environ.get("OSINT_UI_HOST", "0.0.0.0")
PORT = int(os.environ.get("OSINT_UI_PORT", "8877"))
APP_ROOT = Path(__file__).resolve().parent
WEB_ROOT = APP_ROOT / "web"


def to_text(report: dict) -> str:
    return core.render_text(report)


class Handler(BaseHTTPRequestHandler):
    server_version = "osint-web-ui/0.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(f"[web-ui] {self.address_string()} - {fmt % args}")

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404, "Not found")
            return

        ctype, _ = mimetypes.guess_type(str(path))
        self.send_response(200)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        payload = self.rfile.read(length)
        if not payload:
            return {}
        return json.loads(payload.decode("utf-8"))

    def _serve_static(self, request_path: str) -> None:
        request_path = request_path.lstrip("/") or "index.html"
        file_path = (WEB_ROOT / request_path).resolve()
        web_root_resolved = WEB_ROOT.resolve()

        if not str(file_path).startswith(str(web_root_resolved)):
            self.send_error(403, "Forbidden")
            return
        if not file_path.exists() or not file_path.is_file():
            self.send_error(404, "Not found")
            return

        self._send_file(file_path)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json({"ok": True, "service": "osint-helper-web-ui"})
            return

        if path == "/":
            path = "/index.html"

        self._serve_static(path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/osint":
            self.send_error(404, "Not found")
            return

        try:
            body = self._read_json()
            mode = str(body.get("mode", "")).strip().lower()

            if not mode:
                raise ValueError("mode is required")

            if mode == "username":
                value = str(body.get("value", "")).strip()
                if not value:
                    raise ValueError("value is required")
                report = core.build_username_report(value, probe=bool(body.get("probe", False)))
            elif mode == "domain":
                value = str(body.get("value", "")).strip()
                if not value:
                    raise ValueError("value is required")
                report = core.build_domain_report(value)
            elif mode == "ip":
                value = str(body.get("value", "")).strip()
                if not value:
                    raise ValueError("value is required")
                report = core.build_ip_report(value)
            elif mode == "email":
                value = str(body.get("value", "")).strip()
                if not value:
                    raise ValueError("value is required")
                report = core.build_email_report(value)
            elif mode == "phone":
                value = str(body.get("value", "")).strip()
                if not value:
                    raise ValueError("value is required")
                report = core.build_phone_report(value)
            elif mode == "asn":
                value = str(body.get("value", "")).strip()
                if not value:
                    raise ValueError("value is required")
                report = core.build_asn_report(value)
            elif mode == "ioc":
                indicators = body.get("indicators")
                if isinstance(indicators, str):
                    indicators = [indicators]
                elif not isinstance(indicators, list):
                    value = str(body.get("value", "")).strip()
                    indicators = [value] if value else []

                values = [str(v).strip() for v in indicators if str(v).strip()]
                if not values:
                    raise ValueError("indicators is required for IOC mode")
                report = core.build_ioc_report(values)
            else:
                raise ValueError(f"unsupported mode: {mode}")

            self._send_json(
                {
                    "ok": True,
                    "mode": mode,
                    "report": report,
                    "text": to_text(report),
                }
            )
        except ValueError as e:
            self._send_json({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            self._send_json(
                {
                    "ok": False,
                    "error": f"unexpected server error: {e}",
                    "trace": traceback.format_exc(),
                },
                status=500,
            )


def main() -> int:
    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"OSINT Helper Web UI running on http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
