#!/usr/bin/env python3
"""
log-sense - API de detecção de anomalias em logs (Blue Team).

Parser simples + regras de assinatura/ comportamental + gera relatório de alerta.
Todos os cenários aqui são Fictícios (simulação). Nada é atacado de verdade.

Uso:
    python3 sensor.py --logs samples/log.txt [--ai]

Saida:
    - Imprime a tela o que detectou
    - Grava alerts/alerte_<timestamp>.txt
"""

import argparse
import datetime
import os
import re
import sys
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
ALERTS = os.path.join(ROOT, "alerts")

# Campos essenciais que o parser extrai do log bruto
FIELD_NAMES = ["timestamp", "level", "event", "user", "ip", "file", "result"]


def parse_line(line):
    """Extrai campos basicos de uma linha do log.

    Supoe um formato similar a syslog/authorization:
        2026-11-11 08:00:01 INFO  login user=adm ip=10.0.0.5 result=failed

    Retorna dict com o que encontrou. Linhas que nao casam sao ignoradas.
    """
    line = line.strip()
    if line.startswith("\ufeff"):
        line = line[1:]
    if not line:
        return None

    # timestamp: 2026-11-11 08:00:01
    m = re.match(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
    timestamp = m.group(1) if m else None

    # level: INFO / WARN / ERROR
    m = re.search(r"\b(INFO|WARN|ERROR|DEBUG)\b", line)
    level = m.group(1) if m else None

    # event: login / access / connect / etc (proxima palavra apos level)
    idx = m.end() if m else 0
    m = re.search(r"\b(login|logout|access|connect|file|cron|ssh|dump|exec)\b", line[idx:])
    event = m.group(1) if m else None

    # campos chave (user, ip, file, result) - abacaxi de pirâmide
    result = None
    user = None
    ip = None
    file_path = None
    for token in line.split():
        if token.startswith("user="):
            user = token.split("=", 1)[1]
        elif token.startswith("ip="):
            ip = token.split("=", 1)[1]
        elif token.startswith("file="):
            file_path = token.split("=", 1)[1]
        elif token.startswith("result="):
            result = token.split("=", 1)[1]

    return {
        "timestamp": timestamp,
        "level": level,
        "event": event,
        "user": user,
        "ip": ip,
        "file": file_path,
        "result": result,
        "raw": line,
    }


def parse_log(path):
    """Lê o arquivo inteiro e retorna lista de dicionarios."""
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                parsed = parse_line(raw)
                if parsed:
                    entries.append(parsed)
    except FileNotFoundError:
        sys.exit(f"[ERRO] 로그 파일을 찾을 수 없음: {path}")
    return entries


# ---- Regras de deteccao (Blue Team) -----------------------------------

def rule_bruteforce(entries):
    """Mais de 5 tentativas de login fracassadas para a *mesma* identidade
    (usuario + IP) no mesmo minuto.

    Agrupa por (minuto, usuario, ip) a fim de nao somar falhas de origens
    diferentes, reduzindo falsos positivos em cenarios onde varios usuarios
    ou IPs atacam ao mesmo tempo sobre o mesmo alvo.

    Eventos sem timestamp, usuario ou IP sao ignorados em vez de agrupados
    de forma ambígua.
    """
    buckets = defaultdict(list)
    for e in entries:
        if e.get("event") != "login" or e.get("result") != "failed":
            continue
        ts = e.get("timestamp") or ""
        minute = ts.rsplit(":", 1)[0] if (":" in ts and ts.strip()) else None
        user = e.get("user")
        ip = e.get("ip")
        # Sem timestamp, usuario ou IP o evento nao possui origem definida:
        # nao podemos agrupar sem gerar falso positivo ou erro.
        if minute is None or user is None or ip is None:
            continue
        buckets[(minute, user, ip)].append(e)

    alerts = []
    for (minute, user, ip), evs in buckets.items():
        if len(evs) >= 5:
            alerts.append({
                "rule": "brute_force",
                "severity": "high",
                "message": f"{len(evs)} tentativas de login falhas no minuto {minute} de {user} (IP {ip})",
                "details": evs,
            })
    return alerts


def rule_anomaly_ip(event_entries):
    """Se a mesma usuario logar de IP diferente num mesmo minuto, provavel cruzamento de tentativas."""
    from collections import defaultdict
    by_minip = defaultdict(list)
    for e in event_entries:
        if e.get("event") == "login" and e.get("result") == "failed" and e.get("ip"):
            by_minip[e["timestamp"]].append(e)

    alerts = []
    for minute, evs in by_minip.items():
        ips = {e["ip"] for e in evs}
        if len(ips) > 1:
            alerts.append({
                "rule": "ip_fingerprint_breach",
                "severity": "medium",
                "message": f"Usuario tentou acesso de duas redes diferentes no minuto {minute} (IPs: {', '.join(sorted(ips))})",
                "details": evs,
            })
    return alerts


def rule_sensitive_file_access(entries, sensitive={"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh/authorized_keys"}):
    """Acesso a arquivo critico."""
    alerts = []
    for e in entries:
        if e.get("event") == "access" and e.get("file") in sensitive:
            alerts.append({
                "rule": "sensitive_file_access",
                "severity": "high",
                "message": f"Usuario {e.get('user')} acessou {e.get('file')} de IP {e.get('ip')}",
                "details": [e],
            })
    return alerts


def rule_dangerous_command(entries, forbidden={"rm -rf /", "mkfs", "chmod 777 /"}):
    """Execucao de comando suspeito."""
    alerts = []
    for e in entries:
        if e.get("event") == "exec" and e.get("result") in forbidden:
            alerts.append({
                "rule": "forbidden_command",
                "severity": "critical",
                "message": f"Comando proibido executado: {e.get('result')}",
                "details": [e],
            })
    return alerts


def rule_sqli(entries):
    """Injecao SQL: parametros com padrões suspeitos (union select, or 1=1, etc.).
    Usa padrões mais restritivos para reduzir falsos positivos.
    """
    alerts = []
    patterns = [
        r"union\s+select",  # UNION SELECT
        r"(?:or|and)\s+\d+\s*=\s*\d+",  # OR 1=1
        r"information_schema",  # enumeracao de esquema
        r"select\s+.*\s+from\s+.*\s*where\s+.*\s*=\s*'",  # SELECT ... WHERE ... = '
        r"(?:drop|delete|update|insert)\s+(?:table|database|exec)",  # DDL
        r"--\s*$",  # comentario SQL no final
        r"/\*",  # comentario SQL bloqueante
        r"sleep\s*\(",  # sleep() SQL
        r"benchmark\s*\(",  # benchmark SQL (MySQL)
    ]
    for e in entries:
        if e.get("event") == "access" and e.get("result") in ("failed", "denied"):
            raw = (e.get("raw") or "").lower()
            for pat in patterns:
                if re.search(pat, raw, re.IGNORECASE):
                    alerts.append({
                        "rule": "sqli_query",
                        "severity": "high",
                        "message": f"Possivel injecao SQL detectada (pads: {re.findall(pat, raw, re.I)[:1]}).",
                        "details": [e],
                    })
                    break
    return alerts


def rule_xss(entries):
    """XCriptografia reflectida: script, javascript: ou eventos no parametro."""
    alerts = []
    patterns = [
        r"<script\b",  # <script>
        r"javascript:",  # javascript:
        r"onerror\s*=",  # onerror=
        r"onload\s*=",  # onload=
        r"<svg\b",  # SVG
    ]
    for e in entries:
        if e.get("event") == "access" and e.get("result") in ("failed", "denied"):
            raw = (e.get("raw") or "").lower()
            for pat in patterns:
                if re.search(pat, raw, re.IGNORECASE):
                    alerts.append({
                        "rule": "xss_reflected",
                        "severity": "medium",
                        "message": f"Possivel XSS no parametro (pads: {re.findall(pat, raw, re.I)[:1]}).",
                        "details": [e],
                    })
                    break
    return alerts


def rule_unauthorized_access(entries, threshold=5, window="10"):
    """Muito acesso nao autorizado (401/403) num curto periodo.
    Sobe a linha e bloqueia possivel brute force HTTP.
    """
    alerts = []
    buckets = defaultdict(list)
    for e in entries:
        if e.get("event") == "access" and e.get("result") in ("failed", "denied"):
            ts = e.get("timestamp") or ""
            minute_key = ts[:15] if ":" in ts else ts
            buckets[minute_key].append(e)

    for minute, evs in buckets.items():
        denied = sum(1 for e in evs if e.get("result") in ("failed", "denied"))
        if denied >= threshold:
            alerts.append({
                "rule": "unauthorized_access",
                "severity": "high",
                "message": f"{denied} acessos nao autorizados ({threshold}+ no minuto {minute}). Possivel brute force HTTP.",
                "details": evs,
            })
    return alerts


def rule_idle_session(entries, idle_threshold=30):
    """Alerta se há uma sessão sem atividade por mais de X minutos.

    Depois de logar, rastreia eventos do mesmo usuário. Se o gap entre eventos
    sucessivos é maior que o threshold (minutos), considera uma possível perda de sessão.
    """
    alerts = []
    # filtra entradas com timestamp valido (evita erro de sort com None)
    filtered = [e for e in entries if e.get("timestamp") and e.get("timestamp", "").strip()]
    if len(filtered) < 2:
        return alerts

    # ordena por timestamp para análise cronológica
    sorted_entries = sorted(filtered, key=lambda e: e.get("timestamp", ""))

    # agrupa por user
    users = defaultdict(list)
    for e in sorted_entries:
        user = e.get("user")
        if user:
            users[user].append(e)

    for user, evts in users.items():
        sessions = []
        for e in evts:
            if e.get("event") == "login" and e.get("result") == "success":
                sessions.append(e)

        for i, login in enumerate(sessions):
            login_time = login.get("timestamp", "")
            # acha o próximo evento do mesmo usuário (apenas o imediatamente seguinte, depois do login)
            next_event = None
            for e in evts:
                if e is login:
                    continue
                # ignora eventos anteriores ao login
                if e.get("timestamp", "") <= login_time:
                    continue
                # só considera atividade do usuário (não eventos de sistema como coleta de logs)
                if e.get("event") in ("login", "access"):
                    f = (e.get("file") or "").lower()
                    if e.get("event") == "access" and any(k in f for k in ("backup", "log", "archive", "tar")):
                        continue
                next_event = e
                break
            if next_event is None:
                continue
            event_time = next_event.get("timestamp", "")
            if not event_time or not login_time:
                continue
            try:
                from datetime import datetime
                t1 = datetime.strptime(login_time[:19], "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(event_time[:19], "%Y-%m-%d %H:%M:%S")
                delta = (t2 - t1).total_seconds() / 60.0
                if delta > idle_threshold:
                    severity = "medium" if delta < 60 else "high"
                    alerts.append({
                        "rule": "idle_session",
                        "severity": severity,
                        "message": f"Sessão do usuário {login.get('user')} inativa por {delta:.0f} minutos",
                        "details": [login, next_event],
                    })
            except (ValueError, TypeError):
                continue
    return alerts


def rule_user_enumeration(entries, threshold=5):
    """Não estimar usuários: login falho para vários usuários diferentes num minuto."""

    logs = [e for e in entries if e.get("event") == "login" and e.get("result") == "failed"]
    users = {}
    for e in logs:
        u = e.get("user")
        ts = e.get("timestamp") or ""
        minute = ts[:15] if (":" in ts and ts.strip()) else ts
        users.setdefault(minute, set()).add(u)

    alerts = []
    for minute, users_in_minute in users.items():
        if len(users_in_minute) >= threshold:
            alerts.append({
                "rule": "user_enumeration",
                "severity": "medium",
                "message": f"Tentativas de login falhas para {len(users_in_minute)} usuarios diferentes no minuto {minute}.",
                "details": [e for e in logs if e.get("timestamp", "")[:15] == minute],
            })
    return alerts


def run_rules(entries):
    """Aplica todas as regras e retorna alertas consolidados."""
    all_alerts = []
    all_alerts += rule_bruteforce(entries)
    all_alerts += rule_sensitive_file_access(entries)
    all_alerts += rule_dangerous_command(entries)
    all_alerts += rule_anomaly_ip(entries)
    all_alerts += rule_sqli(entries)
    all_alerts += rule_xss(entries)
    all_alerts += rule_unauthorized_access(entries)
    all_alerts += rule_idle_session(entries)
    all_alerts += rule_user_enumeration(entries)
    return all_alerts


def write_alert_report(entries, alerts, out_path):
    """Gera um relatorio simples markdown no alerts/."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    lines = []
    lines.append("=" * 72)
    lines.append("RELATORIO DE ALERTAS - log-sense")
    lines.append(f"Gerado em: {datetime.datetime.now().isoformat()}")
    lines.append(f"Log analisado: {entries and entries[0]['raw'][:0] or ''}...")
    lines.append(f"Total de eventos lidos: {len(entries)}")
    lines.append(f"Total de alertas: {len(alerts)}")
    lines.append("=" * 72)
    lines.append("")
    if not alerts:
        lines.append("[SEM ALERTAS] Nenhuma anomalia foi detectada.")
    else:
        for i, a in enumerate(alerts, 1):
            lines.append(f"[ALERTA {i}] regra={a['rule']} severidade={a['severity'].upper()}")
            lines.append(f"        descricao: {a['message']}")
            for d in a.get("details", []):
                lines.append(f"        dado: {d.get('raw')}")
    lines.append("")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return out_path


def main():
    ap = argparse.ArgumentParser(description="log-sense - deteccao de anomalias em logs.")
    ap.add_argument("--logs", required=True, help="Caminho para o arquivo de log de entrada.")
    ap.add_argument("--ai", action="store_true", help="(n/a no MVP) para ligar assistive AI.")
    args = ap.parse_args()

    if not os.path.exists(args.logs):
        sys.exit(f"[ERRO] Arquivo nao encontrado: {args.logs}")

    entries = parse_log(args.logs)
    if not entries:
        sys.exit("[ERRO] Nenhum evento reconhecido no log fornecido.")

    alerts = run_rules(entries)

    os.makedirs(ALERTS, exist_ok=True)
    out_path = os.path.join(ALERTS, f"alerte_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt")
    out_path = write_alert_report(entries, alerts, out_path)

    print(f"[log-sense] eventos lidos: {len(entries)}")
    print(f"[log-sense] alertas gerados: {len(alerts)}")
    print(f"[log-sense] relatorio salvo em: {out_path}")
    for a in alerts:
        print(f"  -[{a['severity'].upper()}] {a['rule']}: {a['message']}")


if __name__ == "__main__":
    main()
