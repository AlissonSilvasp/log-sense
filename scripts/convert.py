#!/usr/bin/env python3
"""
convert.py - Conversor de logs reais para o formato canônico do sensor.

O sensor.py lê linhas no formato canônico:
    YYYY-MM-DD HH:MM:SS LEVEL EVENT user=... ip=... [file=...] [result=...]

Esse script traduz de formatos comuns (nginx, auth, JSON, CSV) e imprime no
canônico, pronto pra ser encaixado no sensor.

Uso:
    python3 scripts/convert.py --input access.log --format nginx > canon.txt
    python3 scripts/sensor.py --logs canon.txt
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone


def _canonical(fields):
    """Formata um dicionário em uma linha de log canônico."""
    ts = fields.get("timestamp") or ""
    level = fields.get("level") or "INFO"
    event = fields.get("event") or ""
    user = fields.get("user") or ""
    ip = fields.get("ip") or ""
    file_path = fields.get("file") or ""
    result = fields.get("result") or ""
    line = f"{ts} {level} {event} user={user} ip={ip}"
    if file_path:
        line += f" file={file_path}"
    if result:
        line += f" result={result}"
    return line


def to_canonical(fields):
    """Alias explícito para `_canonical` (compatibilidade com o padrão antigo)."""
    return _canonical(fields)


def convert_nginx(line):
    parts = line.split()
    if len(parts) < 10:
        return None
    try:
        ts = parts[3].lstrip("[").rstrip("]")
        rc = parts[8]
    except IndexError:
        return None
    level = "WARN" if rc in ("401", "403", "404", "500") else "INFO"
    if "GET /login" in line or "POST /login" in line:
        event = "login"
        user = None
        ip = parts[0]
        file_path = None
        result = "success" if rc == "200" else "failed"
    elif "GET /etc" in line or "POST /etc" in line:
        event = "access"
        user = "adm"
        ip = parts[0]
        file_path = parts[6] if len(parts) > 6 else None
        result = "success" if rc == "200" else "denied"
    else:
        return None
    return {"timestamp": ts, "level": level, "event": event, "user": user,
            "ip": ip, "file": file_path, "result": result}


def convert_auth(line):
    line = line.strip()
    if not ("Failed password" in line or "Accepted" in line or "session opened" in line):
        return None

    #timestamp: "Nov 11 15:22:10" -> "2026-11-11 15:22:10"
    m = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if not m:
        return None
    month, day, time = m.group(1).split()
    ts = f"2026-11-11 {time}"

    result = None
    user = None
    ip = None
    event = None

    if "Failed password" in line:
        event = "login"
        result = "failed"
        fm = re.search(r"for\s+(\S+?)\s+from", line)
        if fm:
            user = fm.group(1)
        im = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
        if im:
            ip = im.group(1)
    elif "Accepted" in line:
        event = "login"
        result = "success"
        fm = re.search(r"for\s+(\S+?)\s+(?:from|port)", line)
        if fm:
            user = fm.group(1)
        im = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
        if im:
            ip = im.group(1)
    elif "session opened" in line:
        event = "login"
        result = "success"
        im = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
        if im:
            ip = im.group(1)

    if event is None:
        return None

    level = "WARN" if result == "failed" else "INFO"
    return {"timestamp": ts, "level": level, "event": event, "user": user,
            "ip": ip, "file": None, "result": result}


def convert_json(line):
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    event = obj.get("event", "")
    if event not in ("login", "access", "exec", "connect"):
        return None
    ts = obj.get("timestamp") or ""
    user = obj.get("user")
    ip = obj.get("ip")
    file_path = obj.get("file")
    result = obj.get("result")
    level = "WARN" if result == "failed" or (file_path and "shadow" in file_path) else "INFO"
    return {"timestamp": ts, "level": level, "event": event, "user": user,
            "ip": ip, "file": file_path, "result": result}


def convert_csv(path):
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except Exception as e:
        sys.exit(f"[convert] erro ao ler CSV: {e}")
    out = []
    for r in rows:
        ts = r.get("timestamp") or r.get("time") or r.get("datetime")
        if not ts:
            continue
        event = r.get("event", "")
        if "login" in str(event).lower():
            event = "login"
        elif "access" in str(event).lower():
            event = "access"
        else:
            event = str(event)
        user = r.get("user")
        ip = r.get("ip") or r.get("src_ip") or r.get("source_ip")
        file_path = r.get("file") or r.get("path") or r.get("uri")
        result = r.get("result") or r.get("status") or r.get("outcome")
        if result == "200":
            result = "success"
        elif result in ("401", "403", "404"):
            result = "failed"
        level = "WARN" if result == "failed" else "INFO"
        out.append({"timestamp": ts, "level": level, "event": event,
                    "user": user, "ip": ip, "file": file_path, "result": result})
    return out


def main():
    ap = argparse.ArgumentParser(description="Converte logs reais para o formato canônico usado pelo sensor.")
    ap.add_argument("--input", required=True, help="Caminho do log bruto.")
    ap.add_argument("--format", required=True, choices=["nginx", "auth", "json", "csv"], help="Formato do log de entrada.")
    args = ap.parse_args()

    lines = open(args.input, encoding="utf-8").read().splitlines()
    hits = 0
    if args.format == "nginx":
        for l in lines:
            r = convert_nginx(l)
            if r:
                print(_canonical(r)); hits += 1
    elif args.format == "auth":
        for l in lines:
            r = convert_auth(l)
            if r:
                print(_canonical(r)); hits += 1
    elif args.format == "json":
        for l in lines:
            r = convert_json(l)
            if r:
                print(_canonical(r)); hits += 1
    elif args.format == "csv":
        for r in convert_csv(args.input):
            print(_canonical(r)); hits += 1
    print(f"[convert] {hits} linhas convertidas para o canônico.", file=sys.stderr)


if __name__ == "__main__":
    main()
