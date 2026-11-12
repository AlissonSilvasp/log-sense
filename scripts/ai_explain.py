#!/usr/bin/env python3
"""
ai_explain.py - Triagem assistida de alertas (Blue Team).

Pega os alertas gerados pelo sensor.py e pergunta a uma LLM (OpenAI-compatible)
para traduzir o alerta para linguagem simples, com indicio de ataque e acao
recomendada. O motor de deteccao segue tendo somente regras.

Depende de variaveis de ambiente:
    LOG_SENSE_API_KEY     - Chave de acesso (OpenAI, OpenRouter, Ollama, LM Studio)
    LOG_SENSE_BASE_URL    - URL do endpoint (padrao: https://api.openai.com/v1)
    LOG_SENSE_MODEL       - Modelo usado (padrao: gpt-4o-mini)

Uso:
    python3 scripts/ai_explain.py --logs samples/log.txt

Saida:
    - Imprime a tela o resultado do LLM
    - Grava alerts/alerte_*_ai.txt (versao com explicacao)
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
ALERTS = os.path.join(ROOT, "alerts")
SAMPLES = os.path.join(ROOT, "samples")

# Importa parser + regras do sensor (sem depender de instalacao)
sys.path.insert(0, BASE)
import sensor
from sensor import parse_log, run_rules

PROMPT = """Voce e um analista de segurança senior ajudando um estagiario de Blue Team.

Abaixo esta um ALERTA detectado em logs de laboratorio (dados ficticios).

REGRAS: (1) Saia em linguagem simples, sem jargao. (2) Indique a acao recomendada
e o nivel de urgencia (imediato, aguardar, watch). (3) Nada pare de fato, apenas
explicar.

Alerta:
{json_alert}

Explicacao:"""

HEADERS = {
    "Authorization": "Bearer {key}",
    "Content-Type": "application/json",
}


def api_key_ok():
    return bool(os.getenv("LOG_SENSE_API_KEY"))


def build_payload(alert, entries):
    context = {
        "timestamp": alert.get("timestamp", ""),
        "rule": alert.get("rule", ""),
        "severity": alert.get("severity", ""),
        "message": alert.get("message", ""),
        "details": [d.get("raw", "") for d in alert.get("details", [])[:3]],
        "log_preview": entries[:2],
    }
    return {"model": os.getenv("LOG_SENSE_MODEL", "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": "Você e um analista assistente de seguranca. Responda sempre em portugues do Brasil, de forma clara e objetiva."},
                {"role": "user", "content": PROMPT.format(json_alert=json.dumps(context, ensure_ascii=False, indent=2))},
            ],
            "temperature": 0.3}


def call_ai(payload):
    api_key = os.getenv("LOG_SENSE_API_KEY")
    base_url = os.getenv("LOG_SENSE_BASE_URL", "https://api.openai.com/v1")
    model = os.getenv("LOG_SENSE_MODEL", "gpt-4o-mini")

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=data,
        headers={**HEADERS, "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body["choices"][0]["message"]["content"].strip()


def explain_alert(alert, entries):
    """Pede a IA para explicar o alerta. Retorna texto ou None se nao disponivel."""
    try:
        payload = build_payload(alert, entries)
        return call_ai(payload)
    except urllib.error.HTTPError as e:
        print(f"[AI] HTTP {e.code}: verifique a chave/base_url")
        return None
    except Exception as e:
        print(f"[AI] erro de conexao: {e}")
        return None


def main():
    ap = argparse.ArgumentParser(description="log-sense - arealeração com IA.")
    ap.add_argument("--logs", required=True, help="Caminho para o arquivo de log.")
    args = ap.parse_args()

    if not api_key_ok():
        sys.exit("[AI] Chave nao configurada. Defina: "
                 "export LOG_SENSE_API_KEY=sua_chave (ou LOG_SENSE_BASE_URL/LOG_SENSE_MODEL)")

    entries = parse_log(args.logs)
    alerts = run_rules(entries)
    print(f"[AI] alertas lidos: {len(alerts)}")

    for a in alerts:
        print(f"[AI] exibicao para: [{a['severity']}] {a['rule']}")
        expl = explain_alert(a, entries)
        if expl:
            print(f"  IA> {expl}")
        else:
            print("  IA> (sem resposta — verifique as variaveis de ambiente)")


if __name__ == "__main__":
    main()
