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


# ------------------------------------------------------------------
# Validadores de argumentos (inteiro_positivo / inteiro_nao_negativo)
# ------------------------------------------------------------------

def test_inteiro_positivo_aceita_valor_valido():
    assert sc.inteiro_positivo("5") == 5


def test_inteiro_positivo_rejeita_zero():
    import argparse
    try:
        sc.inteiro_positivo("0")
        assert False, "deveria ter rejeitado 0"
    except argparse.ArgumentTypeError:
        pass


def test_inteiro_positivo_rejeita_negativo():
    import argparse
    try:
        sc.inteiro_positivo("-3")
        assert False, "deveria ter rejeitado valor negativo"
    except argparse.ArgumentTypeError:
        pass


def test_inteiro_nao_negativo_aceita_zero():
    assert sc.inteiro_nao_negativo("0") == 0


def test_inteiro_nao_negativo_rejeita_negativo():
    import argparse
    try:
        sc.inteiro_nao_negativo("-1")
        assert False, "deveria ter rejeitado valor negativo"
    except argparse.ArgumentTypeError:
        pass


# ------------------------------------------------------------------
# Severidade
# ------------------------------------------------------------------

def test_severidade_no_limite_e_media():
    assert sc.calcular_severidade(5, 5) == "médio"


def test_severidade_dobro_do_limite_e_alta():
    assert sc.calcular_severidade(10, 5) == "alto"


def test_severidade_muito_acima_e_critica():
    assert sc.calcular_severidade(30, 5) == "crítico"


def test_severidade_abaixo_do_limite_e_baixa():
    assert sc.calcular_severidade(3, 5) == "baixo"


# ------------------------------------------------------------------
# Whitelist de IPs
# ------------------------------------------------------------------

def test_whitelist_aceita_ip_solto_e_cidr():
    redes, invalidos = sc.carregar_whitelist("192.168.0.0/16, 10.0.0.5")
    assert invalidos == []
    assert len(redes) == 2


def test_whitelist_marca_entrada_invalida():
    redes, invalidos = sc.carregar_whitelist("192.168.0.0/16, isso-nao-e-ip")
    assert invalidos == ["isso-nao-e-ip"]


def test_ip_na_whitelist_por_cidr():
    redes, _ = sc.carregar_whitelist("192.168.0.0/16")
    assert sc.ip_na_whitelist("192.168.55.10", redes) is True
    assert sc.ip_na_whitelist("8.8.8.8", redes) is False


def test_brute_force_ignora_ip_na_whitelist():
    registros = [
        sc.novo_registro(ip="10.0.0.5", data=datetime(2026, 1, 1, 12, 0, i),
                          usuario="root", tipo="falha")
        for i in range(10)
    ]
    redes, _ = sc.carregar_whitelist("10.0.0.5")
    alertas = sc.detectar_brute_force(registros, limite=5, janela=300, whitelist=redes)
    assert alertas == []


# ------------------------------------------------------------------
# Brute force distribuído
# ------------------------------------------------------------------

def test_brute_force_distribuido_detecta_varios_ips_mesmo_usuario():
    base = datetime(2026, 1, 1, 12, 0, 0)
    registros = []
    for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]):
        registros.append(sc.novo_registro(
            ip=ip, data=base + timedelta(seconds=i * 5), usuario="admin", tipo="falha"))
    alertas = sc.detectar_brute_force_distribuido(
        registros, limite=4, janela=300, minimo_ips=3)
    assert len(alertas) == 1
    assert alertas[0]["usuario"] == "admin"
    assert alertas[0]["ips_distintos"] == 4


def test_brute_force_distribuido_ignora_um_unico_ip():
    base = datetime(2026, 1, 1, 12, 0, 0)
    registros = [
        sc.novo_registro(ip="1.1.1.1", data=base + timedelta(seconds=i),
                          usuario="admin", tipo="falha")
        for i in range(5)
    ]
    alertas = sc.detectar_brute_force_distribuido(
        registros, limite=5, janela=300, minimo_ips=3)
    assert alertas == []


# ------------------------------------------------------------------
# Formato JSON estruturado
# ------------------------------------------------------------------

def test_parseia_linha_json_com_campos_padrao():
    linha = '{"ip": "1.1.1.1", "status": 404, "path": "/admin"}'
    registros = sc.parsear_linhas([linha], "json")
    assert registros[0]["ip"] == "1.1.1.1"
    assert registros[0]["status"] == 404
    assert registros[0]["caminho"] == "/admin"


def test_parseia_linha_json_com_nomes_de_campo_alternativos():
    linha = '{"client_ip": "2.2.2.2", "response_status": 200, "url": "/x"}'
    registros = sc.parsear_linhas([linha], "json")
    assert registros[0]["ip"] == "2.2.2.2"
    assert registros[0]["status"] == 200


def test_json_invalido_vira_registro_ignorado():
    registros = sc.parsear_linhas(["isto nao e json{{{"], "json")
    assert registros[0]["tipo"] == "ignorada"


def test_deteccao_automatica_reconhece_formato_json():
    linhas = ['{"ip": "1.1.1.1", "status": 404, "path": "/a"}'] * 5
    assert sc.detectar_formato(linhas) == "json"


def test_deteccao_automatica_reconhece_nginx_como_apache():
    linha = ('203.0.113.7 - - [17/Sep/2026:09:00:00 +0000] '
             '"GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0"')
    assert sc.detectar_formato([linha] * 5) == "apache"
