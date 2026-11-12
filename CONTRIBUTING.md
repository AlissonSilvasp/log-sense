# Como contribuir no log-sense

O log-sense é um projeto **didático** de segurança da informação. Toda contribuição
é bem-vinda — desde um teste de regra até uma formatação de log nova.

Visão geral:
- `scripts/sensor.py` — engine de detecção (parser + regras)
- `scripts/convert.py` — converto de formats reais para o canônico
- `scripts/ai_explain.py` — IA (opcional, pede chave)
- `dashboard.py` + `dashboard.html` — painel web local

---

## Como adicionar uma regra de detecção

1. Abra `scripts/sensor.py`.
2. Crie uma função `rule_xxx(entries)` que receba a lista de entradas e
   retorne uma lista de alertas (`list[dict]`).
3. Cada alerta deve ter:
   - `rule` (str) – nome da regra
   - `severity` ("low"|"medium"|"high"|"critical")
   - `message` (str) – descrição curta
   - `details` (list[dict]) – evidências, opcional
4. Chame sua regra dentro de `run_rules()`.

Exemplo:

```python
def rule_bruteforce(entries):
    alerts = []
    # ... sua lógica ...
    return alerts
```

---

## Como adicionar um conversor de formato real

1. Abra `scripts/convert.py`.
2. Crie uma função `convert_X( linha )` que receba uma linha e
   retorne um dicionário ou None.
3. Se o campo não existir, não quebre — retorne `None`.

```python
def convert_X(line):
    if "palavrao" not in line:
        return None
    return {"user": ..., "ip": ..., "event": "login", "result": "failed"}
```

---

## Como rodar a aplicação

```bash
pip install -r requirements.txt
python dashboard.py
# abra http://localhost:8765
```

## Testes

```bash
pip install pytest
pytest
```

Embaixo, um exemplo de `tests/test_sensor.py`:

```python
from scripts import sensor

def _parse(lines):
    return sensor.parse_log("\n".join(lines))

def test_can_identify_bruteforce():
    log = [
        "2026-11-11 08:00:00 WARN login user=root ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:01 WARN login user=root ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:02 WARN login user=root ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:03 WARN login user=root ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:04 WARN login user=root ip=10.0.0.5 result=failed",
    ]
    alerts = sensor.run_rules(_parse(log))
    assert any(a["rule"] == "brute_force" for a in alerts)
```

---

## Padronização de commits

- `fix:` – correção
- `feat:` – nova feature
- `docs:` – somente documentação
- `test:` – adição ou alteração de testes
- `refactor:` – alteração sem mudança de comportamento

---

## O que **não** fazer

- Nunca envie chaves, senhas ou arquivos de log reais.
- Nunca teste em produção ou em máquinas alheias sem autorização.
- Nunca adicione dependências desnecessárias.

---

Se tiver dúvida, abra uma Issue ou me chama. Obrigado pela contribuição! 🎉
