# -*- coding: utf-8 -*-
"""
Testes unitários básicos do SCARFACE.

Rodar com:
    pip install pytest --break-system-packages
    pytest test_scarface.py -v
"""

from datetime import datetime, timedelta

import scarface as sc


# ------------------------------------------------------------------
# janela_deslizante
# ------------------------------------------------------------------

def test_janela_deslizante_agrupa_eventos_proximos():
    base = datetime(2026, 1, 1, 12, 0, 0)
    tempos = [base + timedelta(seconds=s) for s in (0, 10, 20, 400, 410)]
    # os 3 primeiros cabem numa janela de 300s; os 2 últimos formam outro grupo
    maximo, ini, fim = sc.janela_deslizante(tempos, janela=300)
    assert maximo == 3
    assert (ini, fim) == (0, 2)


def test_janela_deslizante_sem_eventos():
    maximo, ini, fim = sc.janela_deslizante([], janela=300)
    assert maximo == 0


# ------------------------------------------------------------------
# Regex de SSH (o bug original: usuario/ip trocados ou vazios)
# ------------------------------------------------------------------

def test_regex_failed_password():
    linha = "Sep 17 09:14:22 srv sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    m = sc.REG_SSH_PADRAO.match(linha)
    assert m is not None
    assert m.group("usuario") == "root"
    assert m.group("ip") == "1.2.3.4"


def test_regex_accepted_password():
    linha = "Sep 17 10:07:45 srv sshd[9]: Accepted password for alice from 198.51.100.22 port 46123 ssh2"
    m = sc.REG_SSH_PADRAO.match(linha)
    assert m is not None
    assert m.group("usuario") == "alice"
    assert m.group("ip") == "198.51.100.22"


def test_regex_invalid_user():
    linha = "Sep 17 10:15:02 srv sshd[5]: Invalid user teste from 45.33.12.9 port 51000"
    m = sc.REG_SSH_INVALIDO.match(linha)
    assert m is not None
    assert m.group("usuario") == "teste"
    assert m.group("ip") == "45.33.12.9"
    # o regex padrão (Failed/Accepted) NÃO deve casar com essa linha
    assert sc.REG_SSH_PADRAO.match(linha) is None


# ------------------------------------------------------------------
# detectar_comprometimento (o bug do falso positivo)
# ------------------------------------------------------------------

def _registro_auth(ip, minutos, tipo, usuario="user"):
    return sc.novo_registro(
        ip=ip,
        data=datetime(2026, 1, 1, 12, 0, 0) + timedelta(minutes=minutos),
        usuario=usuario,
        tipo=tipo,
    )


def test_comprometimento_detecta_sucesso_logo_apos_falhas():
    registros = [
        _registro_auth("1.2.3.4", 0, "falha"),
        _registro_auth("1.2.3.4", 1, "falha"),
        _registro_auth("1.2.3.4", 2, "falha"),
        _registro_auth("1.2.3.4", 3, "sucesso"),  # 1 min depois da última falha
    ]
    alertas = sc.detectar_comprometimento(registros, janela=600, minimo_falhas=3)
    assert len(alertas) == 1
    assert alertas[0]["ip"] == "1.2.3.4"


def test_comprometimento_ignora_sucesso_distante_no_tempo():
    """Este é o caso que gerava falso positivo na versão original:
    uma falha isolada há dias, seguida de um login legítimo sem relação."""
    registros = [
        _registro_auth("9.9.9.9", 0, "falha"),
        _registro_auth("9.9.9.9", 60 * 24 * 5, "sucesso"),  # 5 dias depois
    ]
    alertas = sc.detectar_comprometimento(registros, janela=600, minimo_falhas=3)
    assert alertas == []


def test_comprometimento_ignora_poucas_falhas():
    registros = [
        _registro_auth("8.8.8.8", 0, "falha"),
        _registro_auth("8.8.8.8", 1, "sucesso"),
    ]
    alertas = sc.detectar_comprometimento(registros, janela=600, minimo_falhas=3)
    assert alertas == []


# ------------------------------------------------------------------
# detectar_ataques
# ------------------------------------------------------------------

def test_detecta_sql_injection():
    registros = [sc.novo_registro(ip="1.1.1.1",
                                  caminho="/produto.php?id=1' OR '1'='1' -- -")]
    alertas = sc.detectar_ataques(registros)
    assert any(a["tipo"] == "SQL Injection" for a in alertas)


def test_detecta_xss():
    registros = [sc.novo_registro(ip="1.1.1.1",
                                  caminho="/busca.php?q=<script>alert(1)</script>")]
    alertas = sc.detectar_ataques(registros)
    assert any(a["tipo"] == "XSS" for a in alertas)


def test_detecta_path_traversal():
    registros = [sc.novo_registro(ip="1.1.1.1",
                                  caminho="/download.php?arquivo=../../etc/passwd")]
    alertas = sc.detectar_ataques(registros)
    assert any(a["tipo"] == "Path Traversal" for a in alertas)


def test_sem_falso_positivo_em_url_normal():
    registros = [sc.novo_registro(ip="1.1.1.1", caminho="/index.html")]
    assert sc.detectar_ataques(registros) == []
