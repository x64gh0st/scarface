# -*- coding: utf-8 -*-
"""
Testes do SCARFACE (scanner de portas).

    pip install pytest
    pytest test_scarface.py -v
"""

import socket
import threading

import pytest

import scarface as sc


# ------------------------------------------------------------------
# Servidor local de teste
# ------------------------------------------------------------------

@pytest.fixture
def servidor_ssh_falso():
    """Abre uma porta local que responde com um banner de SSH."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    porta = srv.getsockname()[1]

    def aceitar():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            c.close()

    threading.Thread(target=aceitar, daemon=True).start()
    yield porta
    srv.close()


def porta_livre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    porta = s.getsockname()[1]
    s.close()
    return porta


# ------------------------------------------------------------------
# parse_portas
# ------------------------------------------------------------------

def test_porta_unica():
    assert sc.parse_portas("80") == [80]


def test_lista_e_faixa():
    assert sc.parse_portas("22,80,100-102") == [22, 80, 100, 101, 102]


def test_todas_as_portas():
    assert len(sc.parse_portas("-")) == 65535


def test_remove_duplicadas():
    assert sc.parse_portas("80,80,79-80") == [79, 80]


@pytest.mark.parametrize("ruim", ["0", "65536", "abc", "90-80", "", "22,,x"])
def test_portas_invalidas(ruim):
    with pytest.raises(ValueError):
        sc.parse_portas(ruim)


# ------------------------------------------------------------------
# expandir_alvos
# ------------------------------------------------------------------

def test_ip_unico():
    assert sc.expandir_alvos(["10.0.0.5"]) == [("10.0.0.5", "10.0.0.5")]


def test_cidr_expande_hosts():
    alvos = sc.expandir_alvos(["192.168.1.0/30"])
    assert [ip for _, ip in alvos] == ["192.168.1.1", "192.168.1.2"]


def test_cidr_grande_demais():
    with pytest.raises(ValueError):
        sc.expandir_alvos(["10.0.0.0/8"])


def test_host_inexistente():
    with pytest.raises(ValueError):
        sc.expandir_alvos(["host-que-nao-existe.invalid"])


def test_remove_alvos_duplicados():
    assert len(sc.expandir_alvos(["10.0.0.5", "10.0.0.5"])) == 1


# ------------------------------------------------------------------
# escaneamento
# ------------------------------------------------------------------

def test_detecta_porta_aberta(servidor_ssh_falso):
    porta, estado, _ = sc.escanear_porta("127.0.0.1", servidor_ssh_falso, 1.0, False)
    assert (porta, estado) == (servidor_ssh_falso, "aberta")


def test_detecta_porta_fechada():
    _, estado, _ = sc.escanear_porta("127.0.0.1", porta_livre(), 1.0, False)
    assert estado == "fechada"


def test_captura_banner_ssh(servidor_ssh_falso):
    _, estado, banner = sc.escanear_porta("127.0.0.1", servidor_ssh_falso, 1.0, True)
    assert estado == "aberta"
    assert banner.startswith("SSH-2.0-OpenSSH")


def test_escanear_host_conta_estados(servidor_ssh_falso):
    livre = porta_livre()
    abertas, fechadas, filtradas = sc.escanear_host(
        "127.0.0.1", [servidor_ssh_falso, livre], 1.0, 10, False)
    assert [a["porta"] for a in abertas] == [servidor_ssh_falso]
    assert fechadas == 1
    assert filtradas == 0


def test_host_local_esta_ativo():
    ativo, latencia = sc.host_ativo("127.0.0.1", 1.0)
    assert ativo is True
    assert latencia >= 0


# ------------------------------------------------------------------
# banner
# ------------------------------------------------------------------

def test_resumir_banner_http_pega_header_server():
    resposta = b"HTTP/1.0 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n"
    assert sc.resumir_banner(resposta) == "nginx/1.25.3"


def test_resumir_banner_vazio():
    assert sc.resumir_banner(b"") is None


def test_resumir_banner_descarta_lixo_binario():
    assert sc.resumir_banner(b"\x00\x01\x02\x03") is None


def test_nome_servico_conhecido():
    assert sc.nome_servico(22) == "ssh"
    assert sc.nome_servico(443) == "https"
