#!/usr/bin/env python3
"""
dashboard.py - Servidor local do log-sense (Blue Team).

Entre em http://localhost:8765  e use o painel:
    - rodar deteccao,
    - ver estatisticas,
    - baixar relatorios.
"""

import json
import mimetypes
import os
import socketserver
import sys
import urllib.parse
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / "scripts"))
import sensor  # noqa: E402

PORT = int(os.getenv("LOG_SENSE_PORT", "8765"))
INDEX_HTML = BASE / "dashboard.html"

HOST = os.getenv("LOG_SENSE_HOST", "0.0.0.0")


def gather_report(log_path):
    entries = sensor.parse_log(log_path)
    alerts = sensor.run_rules(entries)
    artifact = sensor.write_alert_report(entries, alerts, BASE / "alerts" / f"dashboard_{log_path.stem}.txt")
    artifact = str(artifact)
    return {
        "events": len(entries),
        "alerts": len(alerts),
        "artifact": artifact,
        "details": alerts,
    }


def artifact_list():
    alerts_dir = BASE / "alerts"
    if not alerts_dir.exists():
        return []
    out = []
    for f in sorted(alerts_dir.glob("*.txt"), reverse=True):
        out.append({
            "name": f.name,
            "size": f.stat().st_size,
            "mtime": int(f.stat().st_mtime),
        })
    return out


def chart_series():
    """Dados para o grafico (alertas por severidade e por regra)."""
    import collections
    alerts = []
    log = BASE / "samples" / "log.txt"
    if log.exists():
        entries = sensor.parse_log(str(log))
        alerts = sensor.run_rules(entries)

    severity = collections.Counter(a["severity"] for a in alerts)
    rule = collections.Counter(a["rule"] for a in alerts)

    return {
        "severity": [
            {"name": "High", "count": severity.get("high", 0), "color": "#f85149"},
            {"name": "Medium", "count": severity.get("medium", 0), "color": "#d29922"},
            {"name": "Low", "count": severity.get("low", 0), "color": "#58a6ff"},
        ],
        "rules": [
            {"name": r, "count": c} for r, c in rule.most_common(8)
        ],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silencia logs do HTTP
        pass

    def _send(self, code, body, content_type="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, payload):
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/" or path == "/index.html":
            if INDEX_HTML.exists():
                self._send(200, INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
            else:
                self._json(500, {"error": "dashboard.html nao encontrado"})
        elif path == "/api/status":
            # No log examined yet - default idle state
            self._json(200, {"events": 0, "alerts": 0, "has_log": False, "log": None})
        elif path == "/api/run":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            logs = params.get("logs", [None])
            ai = params.get("ai", ["0"])
            log_path = logs[0] if logs and logs[0] else str(BASE / "samples" / "log.txt")
            p = Path(log_path)
            if not p.exists():
                self._json(400, {"error": f"log nao encontrado: {log_path}"})
                return
            try:
                r = gather_report(p)
            except Exception as e:
                self._json(500, {"error": str(e)})
                return
            self._json(200, {"ok": True, **r, "ai": ai == "1"})
        elif path == "/api/upload":
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                self._json(400, {"error": "Corpo vazio"})
                return
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
                content = data.get("content")
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("corpo deve conter 'content' (texto do log)")
            except Exception as e:
                self._json(400, {"error": f"corpo invalido: {e}"})
                return
            import tempfile
            import os
            temp_dir = BASE / "uploads"
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = temp_dir / f"upload_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(temp_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            self._json(200, {"ok": True, "path": str(temp_path), "filename": temp_path.name})
        elif path == "/api/artifacts":
            self._json(200, {"files": artifact_list()})
        elif path.startswith("/api/artifacts/"):
            name = os.path.basename(path.split("/", 3)[3])
            f = BASE / "alerts" / name
            if not f.exists():
                self._json(404, {"error": "relatorio nao encontrado"})
                return
            self._send(200, f.read_bytes(), "text/plain; charset=utf-8")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/run":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            logs = body.get("logs") or str(BASE / "samples" / "log.txt")
            ai = bool(body.get("ai", False))
            p = Path(logs)
            if not p.exists():
                self._json(400, {"error": f"log nao encontrado: {logs}"})
                return
            try:
                r = gather_report(p)
            except Exception as e:
                self._json(500, {"error": str(e)})
                return
            self._json(200, {"ok": True, **r, "ai": ai})
        elif path == "/api/upload":
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                self._json(400, {"error": "Corpo vazio"})
                return
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
                content = data.get("content")
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("corpo deve conter 'content' (texto do log)")
            except Exception as e:
                self._json(400, {"error": f"corpo invalido: {e}"})
                return
            import tempfile
            import os
            temp_dir = BASE / "uploads"
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = temp_dir / f"upload_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(temp_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            self._json(200, {"ok": True, "path": str(temp_path), "filename": temp_path.name})
        else:
            self._json(404, {"error": "not found"})


def main():
    os.makedirs(BASE / "alerts", exist_ok=True)
    print(f"[dashboard] Handlers: do_GET, do_POST loaded", flush=True)
    print(f"[dashboard] Routes: /api/status, /api/run, /api/upload, /api/artifacts", flush=True)
    with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}"
        print(f"[dashboard] log-sense roadando em {url}")
        print(f"        script: {BASE / 'scripts' / 'sensor.py'}")
        print(f"        sample: {BASE / 'samples' / 'log.txt'}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[dashboard] encerrado.")


if __name__ == "__main__":
    main()
