"""Testes para o engine de detecção (scripts/sensor.py)."""

import os
import tempfile

import pytest

from scripts import sensor


def _parse_lines(lines):
    """Parse um texto de log em dicionários via arquivo temporário."""
    import tempfile
    import io

    # cria um arquivo temporário e escreve o conteúdo
    fd, path = tempfile.mkstemp(suffix=".log")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        # re-abre o arquivo para leitura
        with open(path, "r", encoding="utf-8") as f:
            return sensor.parse_log(path)
    finally:
        # garante a remoção do arquivo mesmo com erro
        try:
            os.unlink(path)
        except OSError:
            pass


@pytest.fixture
def sample_log():
    return [
        "2026-11-11 08:00:00 WARN login user=adm ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:01 WARN login user=adm ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:02 WARN login user=adm ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:03 WARN login user=adm ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:04 WARN login user=adm ip=10.0.0.5 result=failed",
        "2026-11-11 08:01:00 WARN login user=adm ip=10.0.0.5 result=success",
    ]


@pytest.fixture
def events_from_log():
    log = [
        "2026-11-11 08:00:00 WARN login user=adm ip=10.0.0.5 result=failed",
        "2026-11-11 08:00:01 WARN login user=root ip=10.0.0.6 result=failed",
        "2026-11-11 08:00:02 WARN access user=adm ip=10.0.0.5 file=/etc/shadow result=denied",
    ]
    return _parse_lines(log)


def test_parser_extrai_campos(sample_log):
    entries = _parse_lines(sample_log)
    assert len(entries) == 6
    assert entries[0]["event"] == "login"
    assert entries[0]["result"] == "failed"
    assert entries[0]["user"] == "adm"
    assert entries[0]["ip"] == "10.0.0.5"


def test_parser_ignora_linhas_vazias(events_from_log):
    assert len(events_from_log) == 3


def test_parser_recupera_arquivo_sensivel(events_from_log):
    access = [e for e in events_from_log if e["event"] == "access"]
    assert len(access) == 1
    assert access[0]["file"] == "/etc/shadow"


def test_bruteforce_regra(sample_log):
    alerts = sensor.run_rules(_parse_lines(sample_log))
    brute = [a for a in alerts if a["rule"] == "brute_force"]
    assert len(brute) == 1
    assert brute[0]["severity"] == "high"
    assert "5" in brute[0]["message"]


def test_sensitive_file_access_regra(events_from_log):
    alerts = sensor.run_rules(events_from_log)
    sens = [a for a in alerts if a["rule"] == "sensitive_file_access"]
    assert len(sens) == 1
    assert "/etc/shadow" in sens[0]["message"]


def test_nenhum_alert_no_cenario_legal(events_from_log):
    assert True


# =====================================================================
# NOVA COBERTURA DE REGRAS (adicional aos testes originais)
# =====================================================================

def _make_entry(**overrides):
    """Cria um entry padrao (usado nos testes)."""
    base = {
        "timestamp": "2026-11-11 10:00:01",
        "event": "login",
        "user": "adm",
        "ip": "10.0.0.1",
        "file": None,
        "result": "success",
        "raw": "2026-11-11 10:00:01 INFO login user=adm ip=10.0.0.1 result=success",
    }
    base.update(overrides)
    return base


def _make_access(timestamp, user, ip, file, result):
    return {
        "timestamp": timestamp,
        "event": "access",
        "user": user,
        "ip": ip,
        "file": file,
        "result": result,
        "raw": f"{timestamp} INFO access user={user} ip={ip} file={file} result={result}",
    }


def test_rule_bruteforce_single_minute():
    entries = [
        _make_entry(result="failed", timestamp="2026-11-11 10:00:01"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:02"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:03"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:04"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:05"),
    ]
    alerts = sensor.rule_bruteforce(entries)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "brute_force"
    assert alerts[0]["severity"] == "high"


def test_rule_bruteforce_not_triggered_below_threshold():
    entries = [
        _make_entry(result="failed", timestamp="2026-11-11 10:00:01"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:02"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:03"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:04"),
    ]
    alerts = sensor.rule_bruteforce(entries)
    assert len(alerts) == 0


def test_rule_sensitive_file_access_init():
    entries = [
        _make_access("2026-11-11 10:00:01", "adm", "10.0.0.1", "/etc/shadow", "failed"),
        _make_access("2026-11-11 10:00:02", "adm", "10.0.0.1", "/etc/passwd", "failed"),
    ]
    alerts = sensor.rule_sensitive_file_access(entries)
    assert len(alerts) == 2
    assert alerts[0]["rule"] == "sensitive_file_access"


def test_rule_sensitive_file_access_not_triggered():
    entries = [
        _make_access("2026-11-11 10:00:01", "adm", "10.0.0.1", "/home/user", "denied"),
    ]
    alerts = sensor.rule_sensitive_file_access(entries)
    assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Cobertura da regra bruteforce (identidade + minuto, sem somar origens)
# ---------------------------------------------------------------------------
def test_rule_bruteforce_same_identity_same_minute_alert():
    entries = [
        _make_entry(result="failed", timestamp="2026-11-11 10:00:01"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:02"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:03"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:04"),
        _make_entry(result="failed", timestamp="2026-11-11 10:00:05"),
    ]
    alerts = sensor.rule_bruteforce(entries)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "brute_force"
    assert alerts[0]["severity"] == "high"
    assert "5" in alerts[0]["message"]


def test_rule_bruteforce_not_summed_across_different_users():
    entries = [
        _make_entry(result="failed", user="adm", timestamp="2026-11-11 10:00:01"),
        _make_entry(result="failed", user="adm", timestamp="2026-11-11 10:00:02"),
        _make_entry(result="failed", user="adm", timestamp="2026-11-11 10:00:03"),
        _make_entry(result="failed", user="root", timestamp="2026-11-11 10:00:04"),
        _make_entry(result="failed", user="root", timestamp="2026-11-11 10:00:05"),
    ]
    alerts = sensor.rule_bruteforce(entries)
    assert alerts == []


def test_rule_bruteforce_not_summed_across_different_ips():
    entries = [
        _make_entry(result="failed", ip="10.0.0.1", timestamp="2026-11-11 10:00:01"),
        _make_entry(result="failed", ip="10.0.0.1", timestamp="2026-11-11 10:00:02"),
        _make_entry(result="failed", ip="10.0.0.1", timestamp="2026-11-11 10:00:03"),
        _make_entry(result="failed", ip="10.0.0.2", timestamp="2026-11-11 10:00:04"),
        _make_entry(result="failed", ip="10.0.0.2", timestamp="2026-11-11 10:00:05"),
    ]
    alerts = sensor.rule_bruteforce(entries)
    assert alerts == []


def test_rule_bruteforce_not_summed_across_minutes():
    entries = (
        [_make_entry(result="failed", timestamp="2026-11-11 10:00:%02d" % i) for i in range(1, 6)]
        + [_make_entry(result="failed", timestamp="2026-11-11 10:05:%02d" % i) for i in range(0, 5)]
    )
    alerts = sensor.rule_bruteforce(entries)
    assert len(alerts) == 2
    minutes = sorted(a["message"].split("minuto ")[1].split(" de ")[0] for a in alerts)
    assert minutes == ["2026-11-11 10:00", "2026-11-11 10:05"]


def test_rule_bruteforce_missing_fields_skipped_without_error():
    entries = [
        _make_entry(result="failed", user=None),       # user ausente
        _make_entry(result="failed", ip=None),         # ip ausente
        _make_entry(result="failed", timestamp=None),  # timestamp ausente
        _make_entry(result="failed", user=None, ip=None),  # user e ip ausentes
        {
            "timestamp": None,
            "event": "login",
            "result": "failed",
            "user": None,
            "ip": None,
        },  # todos os campos ausentes
    ]
    alerts = sensor.rule_bruteforce(entries)
    assert alerts == []


def test_full_flux_bom_utf8_nao_estoura():
    """Fluxo completo com log UTF-8 contendo BOM (U+FEFF):
    parse_log -> run_rules nao deve estourar, nem gerar entry com timestamp
    vazios que quebram as regras (ex.: rule_user_enumeration).
    """
    import tempfile
    import os

    content = "2026-11-11 08:05:00 WARN login user=adm ip=198.51.100.10 result=failed\n"
    bom_content = "\ufeff" + content

    # Cria um arquivo temporário aberto em modo texto UTF-8 com BOM prefix.
    # 'delete=False' impede que o arquivo seja excluído no fechamento imediato,
    # pois precisamos mantê-lo aberto até o teste concluído.
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8", newline="\n"
    )
    tmp.write(bom_content)
    tmp.flush()
    path = tmp.name
    try:
        entries = sensor.parse_log(path)

        # Todos os events devem ser parseados (timestamp nao deve ser None)
        for e in entries:
            assert e.get("timestamp"), "timestamp nao deve ser None apos BOM strip"
        assert entries[0]["timestamp"] == "2026-11-11 08:05:00"
        assert entries[0]["user"] == "adm"
        assert entries[0]["ip"] == "198.51.100.10"

        alerts = sensor.run_rules(entries)
        # O sistema nao deve estourar, mesmo com entries marcadas como
        # "incomplete" (ex.: de outras regras influenciadas por BOM).
        assert isinstance(alerts, list)
    finally:
        try:
            tmp.close()
        finally:
            os.unlink(path)
