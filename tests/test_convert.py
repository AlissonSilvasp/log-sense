"""Testes para os conversores (scripts/convert.py)."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import convert  # noqa: E402


# =====================================================================
# CONVERSAO: Nginx
# =====================================================================

def test_convert_nginx_login_success():
    line = '192.168.1.1 - - [11/Nov/2026:14:22:10 +0000] "GET /login HTTP/1.1" 200 "-" "Mozilla/5.0"'
    entry = convert.convert_nginx(line)
    assert entry is not None
    assert entry["event"] == "login"
    assert entry["result"] == "success"
    assert entry["ip"] == "192.168.1.1"


def test_convert_nginx_401():
    line = '192.168.1.1 - - [11/Nov/2026:14:22:10 +0000] "POST /login HTTP/1.1" 401 "-" "Mozilla/5.0"'
    entry = convert.convert_nginx(line)
    assert entry is not None
    assert entry["result"] == "failed"
    assert entry["level"] == "WARN"


def test_convert_nginx_access():
    line = '192.168.1.1 - - [11/Nov/2026:14:22:10 +0000] "GET /etc/passwd HTTP/1.1" 403 "-" "Mozilla/5.0"'
    entry = convert.convert_nginx(line)
    assert entry is not None
    assert entry["event"] == "access"
    assert entry["file"] == "/etc/passwd"
    assert entry["result"] == "denied"


def test_convert_nginx_invalid():
    assert convert.convert_nginx("invalid log line") is None


# =====================================================================
# CONVERSAO: AUTH (syslog)
# =====================================================================

def test_convert_auth_failed():
    line = "Nov 11 15:22:10 server sshd[1234]: Failed password for admin from 1.2.3.4 port 22 ssh2"
    entry = convert.convert_auth(line)
    assert entry is not None
    assert entry["event"] == "login"
    assert entry["result"] == "failed"
    assert entry["user"] == "admin"
    assert entry["ip"] == "1.2.3.4"
    assert entry["level"] == "WARN"


def test_convert_auth_accepted():
    line = "Nov 11 15:22:10 server sshd[1234]: Accepted password for root from 5.6.7.8 port 443 ssh2"
    entry = convert.convert_auth(line)
    assert entry is not None
    assert entry["event"] == "login"
    assert entry["result"] == "success"
    assert entry["user"] == "root"
    assert entry["ip"] == "5.6.7.8"
    assert entry["level"] == "INFO"


def test_convert_auth_session_opened():
    line = "Nov 11 15:22:10 server sshd[1234]: session opened for user adm from 9.10.11.12 port 22"
    entry = convert.convert_auth(line)
    assert entry is not None
    assert entry["event"] == "login"
    assert entry["result"] == "success"
    assert entry["ip"] == "9.10.11.12"


def test_convert_auth_invalid():
    assert convert.convert_auth("invalid log line") is None


# =====================================================================
# CONVERSAO: JSON
# =====================================================================

def test_convert_json_login():
    line = json.dumps({
        "timestamp": "2026-11-11T10:00:01Z",
        "event": "login",
        "user": "adm",
        "ip": "10.0.0.1",
        "result": "success",
    })
    entry = convert.convert_json(line)
    assert entry is not None
    assert entry["event"] == "login"
    assert entry["result"] == "success"


def test_convert_json_access():
    line = json.dumps({
        "timestamp": "2026-11-11T10:00:02Z",
        "event": "access",
        "user": "adm",
        "ip": "10.0.0.1",
        "file": "/etc/shadow",
        "result": "denied",
    })
    entry = convert.convert_json(line)
    assert entry is not None
    assert entry["event"] == "access"
    assert entry["file"] == "/etc/shadow"


def test_convert_json_invalid():
    assert convert.convert_json("invalid json {") is None


def test_convert_json_unsupported_event():
    line = json.dumps({"event": "unknown", "timestamp": "2026-11-11T10:00:01Z"})
    assert convert.convert_json(line) is None


# =====================================================================
# CONVERSAO: CSV
# =====================================================================

def test_convert_csv(tmp_path):
    csv_file = tmp_path / "access.csv"
    csv_file.write_text(
        "timestamp,event,user,ip,path,result\n"
        "2026-11-11 10:00:01,login,adm,10.0.0.1,/home,200\n"
        "2026-11-11 10:00:02,access,adm,10.0.0.1,/etc/shadow,403\n",
        encoding="utf-8",
    )
    entries = convert.convert_csv(str(csv_file))
    assert len(entries) == 2
    assert entries[0]["event"] == "login"
    assert entries[0]["result"] == "success"
    assert entries[1]["result"] == "failed"


def test_convert_csv_missing_timestamp(tmp_path):
    csv_file = tmp_path / "access.csv"
    csv_file.write_text(
        "event,user,ip,path,result\n"
        "login,adm,10.0.0.1,/home,200\n",
        encoding="utf-8",
    )
    entries = convert.convert_csv(str(csv_file))
    assert len(entries) == 0


# =====================================================================
# FUNCAO: _canonical
# =====================================================================

def test_canonical_format():
    fields = {
        "timestamp": "2026-11-11 10:00:01",
        "level": "INFO",
        "event": "login",
        "user": "adm",
        "ip": "10.0.0.1",
        "file": "/etc/shadow",
        "result": "failed",
    }
    line = convert._canonical(fields)
    assert "2026-11-11 10:00:01" in line
    assert "INFO" in line
    assert "login" in line
    assert "user=adm" in line
    assert "ip=10.0.0.1" in line
    assert "file=/etc/shadow" in line
    assert "result=failed" in line
