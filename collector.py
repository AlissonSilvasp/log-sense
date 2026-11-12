#!/usr/bin/env python3
"""
collector.py - Coletor de logs e detetor de anomalias (Blue Team, modo standalone).

Executa uma maquina que voce controla e lê os logs locais, convert
os para o formato canonico e aplica as regras de deteccao.

Uso:
    # rodar em modo interativo (precisa do Python)
    python3 collector.py --paths "C:/Windows" "C:/ProgramData" --machine minha-maquina

    # embalar em um unico .exe (sem precisar instalar Python no alvo):
    pip install pyinstaller
    pyinstaller --onefile --name log-sense-collector --add-data "scripts;scripts" collector.py

    # entao basta rodar o .exe gerado em qualquer maquina (Windows):
    log-sense-collector.exe --paths "C:/Windows" --machine estacao-01

Saida:
    reports/relatorio_<data>_<hora>.txt
    prints os alertas encontrados.
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / "scripts"))
import sensor  # noqa: E402
import convert  # noqa: E402

# Padroes de caminhos de log para Windows e Linux
DEFAULT_PATHS = {
    "windows": [
        "C:/Windows",
        "C:/ProgramData",
        "C:/Users",
    ],
    "linux": [
        "/var/log",
        "/var/log/syslog",
        "/var/log/auth.log",
    ],
}


def find_log_files(paths):
    """Acha logs em arquivos ou pastas. Respeita .log, .txt, .json, .csv."""
    files = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            print(f"[!] Caminho nao encontrado: {p}")
            continue
        if path.is_dir():
            files.extend([
                f for f in path.rglob("*")
                if f.is_file() and f.suffix.lower() in (".log", ".txt", ".json", ".csv")
            ])
        else:
            files.append(path)
    return files


def detect_format(path, lines):
    """Tenta advinhar o formato do log a partir da extensao e do inicio."""
    ext = path.suffix.lower()
    if ext == ".json":
        return "json"
    if ext == ".csv":
        return "csv"
    if not lines:
        return "nginx"
    first = lines[0].lower()
    # logs que falam de auth
    if "failed password" in first or "accepted" in first or "session opened" in first:
        return "auth"
    if first.startswith("{") or "timestamp" in first and "," in first:
        return "json"
    return "nginx"


def analyze_file(path):
    """Lê um log, converte e detecta. Retorna (nome, entradas, alertas)."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] nao foi possivel ler {path.name}: {e}")
        return None, [], []

    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return None, [], []

    fmt = detect_format(path, lines)
    conv_map = {"auth": convert.convert_auth, "nginx": convert.convert_nginx,
                "json": convert.convert_json}

    converted = []
    if fmt in conv_map:
        for l in lines:
            r = conv_map[fmt](l)
            if r:
                converted.append(r)
    elif fmt == "csv":
        converted.extend(convert.convert_csv(str(path)))
    elif fmt == "nginx":
        for l in lines:
            r = conv_map["nginx"](l)
            if r:
                converted.append(r)

    if not converted:
        return path.name, [], []

    # sensor.parse_line entende o formato canonico e retorna dict.
    entries = [p for p in map(sensor.parse_line, converted) if p]
    alerts = sensor.run_rules(entries)
    return path.name, entries, alerts


def main():
    ap = argparse.ArgumentParser(description="log-sense-collector - leitura de logs e deteccao.")
    ap.add_argument("paths", nargs="+", help="Caminhos de logs ou pastas (ex: C:/Windows).")
    ap.add_argument("--machine", default="workstation",
                    help="Nome da maquina / entidade (padr: workstation).")
    ap.add_argument("--os", default="windows", choices=["windows", "linux"],
                    help="Sistema alvo (ajuda a definir caminhos default).")
    ap.add_argument("--output", default=None, help="Caminho do relatorio.")
    args = ap.parse_args()

    # Se nenhum path foi passado, usa o padrao do OS
    if not args.paths:
        args.paths = DEFAULT_PATHS.get(args.os, ["C:/Windows", "C:/ProgramData"])

    files = find_log_files(args.paths)
    if not files:
        print("Nenhum log encontrado nas pastas informadas.")
        return

    results = []
    for f in sorted(files):
        name, entries, alerts = analyze_file(f)
        if alerts or entries:
            results.append((name, entries, alerts))
            print(f"[LOGS] {f.name} ({len(entries)} eventos lidos, {len(alerts)} alertas)")

    # relatorio
    out = Path(args.output) if args.output else Path(BASE / "reports" / f"relatorio_{datetime.now():%Y%m%d_%H%M%S}.txt")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("RELATORIO DE DETECCAO - log-sense-collector\n")
        fh.write(f"Maquina: {args.machine}\n")
        fh.write(f"Gerado em: {datetime.now().isoformat()}\n")
        fh.write(f"Logs analisados: {len(files)}\n")
        fh.write(f"Alertas encontrados: {sum(len(a) for _,_,a in results)}\n")
        fh.write("=" * 60 + "\n")
        for name, entries, alerts in results:
            fh.write(f"\n>>> LOG: {name}\n")
            for a in alerts:
                fh.write(f"  [{a['severity'].upper()}] {a['rule']}: {a['message']}\n")

    print(f"\nRelatorio salvo em: {out}")


if __name__ == "__main__":
    main()
