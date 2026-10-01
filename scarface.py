#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCARFACE - scanner de portas TCP simples, inspirado no nmap.

O que faz:
  - descobre se o host está ativo (sem precisar de root)
  - escaneia portas TCP (lista, faixa, as mais comuns ou todas)
  - identifica o serviço de cada porta aberta
  - opcionalmente lê o banner/versão do serviço (-sV)
  - aceita IP, nome de host ou faixa CIDR (192.168.0.0/24)
  - salva o resultado em JSON

Exemplos:
  python scarface.py 192.168.0.1
  python scarface.py scanme.nmap.org -p 22,80,443 -sV
  python scarface.py 192.168.0.0/24 -F
  python scarface.py 10.0.0.5 -p-  -t 300 -o resultado.json
  python scarface.py localhost -Pn

USE APENAS EM SISTEMAS SEUS OU COM AUTORIZAÇÃO EXPLÍCITA.

by DevPedroHenrique
"""

import argparse
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "3.0.0"

# ------------------------------------------------------------------
# CONFIGURAÇÃO
# ------------------------------------------------------------------

# Portas mais comuns (usadas com -F)
TOP_PORTAS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143,
    161, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2375, 3000, 3128, 3306, 3389, 4444, 5000,
    5060, 5432, 5601, 5672, 5900, 5985, 6379, 6443, 7001, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017,
]

# Nomes de serviço (fallback caso o sistema não tenha /etc/services)
SERVICOS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 587: "submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

PORTAS_HTTP = {80, 81, 8000, 8008, 8080, 8081, 8888, 9000, 9090}
PORTAS_TLS = {443, 8443}
PORTAS_PING = (80, 443, 22, 445, 3389, 8080)  # usadas para saber se o host está ativo
LIMITE_HOSTS = 4096

CORES = {"verde": "\033[92m", "amarelo": "\033[93m", "ciano": "\033[96m",
         "vermelho": "\033[91m", "negrito": "\033[1m", "fim": "\033[0m"}

BANNER = r"""
  ___  ___   _   ___ ___ _   ___ ___
 / __|/ __| /_\ | _ \ __/_\ / __| __|
 \__ \ (__ / _ \|   / _/ _ \ (__| _|
 |___/\___/_/ \_\_|_\_/_/ \_\___|___|
  scanner de portas TCP  |  by DevPedroHenrique"""


def pintar(texto, estilo, ativo=True):
    if not ativo or estilo not in CORES:
        return texto
    return CORES[estilo] + texto + CORES["fim"]


def terminal_suporta_cor():
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # habilita códigos ANSI no console do Windows 10+
    return True


# ------------------------------------------------------------------
# ENTRADA: PORTAS E ALVOS
# ------------------------------------------------------------------

def parse_portas(texto):
    """Converte '22,80,8000-8100' (ou '-' para todas) em lista ordenada."""
    texto = texto.strip()
    if texto in ("-", "all", "todas"):
        return list(range(1, 65536))
    portas = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            ini, _, fim = parte.partition("-")
            ini, fim = int(ini), int(fim)
        else:
            ini = fim = int(parte)
        if not (1 <= ini <= fim <= 65535):
            raise ValueError(f"porta fora do intervalo 1-65535: {parte}")
        portas.update(range(ini, fim + 1))
    if not portas:
        raise ValueError("nenhuma porta informada")
    return sorted(portas)


def expandir_alvos(itens):
    """Transforma IPs, CIDRs e nomes de host em uma lista de (nome, ip)."""
    alvos = []
    for item in itens:
        try:
            rede = ipaddress.ip_network(item, strict=False)
        except ValueError:
            rede = None

        if rede is not None:
            if rede.version != 4:
                raise ValueError(f"apenas IPv4 é suportado: {item}")
            if rede.num_addresses > LIMITE_HOSTS:
                raise ValueError(f"faixa muito grande ({rede.num_addresses} IPs, "
                                 f"máximo {LIMITE_HOSTS}): {item}")
            for ip in (list(rede.hosts()) or list(rede)):
                alvos.append((str(ip), str(ip)))
        else:
            try:
                ip = socket.gethostbyname(item)
            except socket.gaierror:
                raise ValueError(f"não consegui resolver o host: {item}")
            alvos.append((item, ip))

    # remove duplicados mantendo a ordem
    vistos, unicos = set(), []
    for nome, ip in alvos:
        if ip not in vistos:
            vistos.add(ip)
            unicos.append((nome, ip))
    return unicos


# ------------------------------------------------------------------
# ESCANEAMENTO
# ------------------------------------------------------------------

def host_ativo(ip, timeout):
    """Descoberta de host por TCP (não precisa de root, ao contrário do ping ICMP).

    Se alguma porta comum ACEITAR ou RECUSAR a conexão, o host está ativo:
    uma recusa (RST) só acontece se alguém do outro lado respondeu.
    Retorna (ativo, latência_em_segundos).
    """
    for porta in PORTAS_PING:
        inicio = time.monotonic()
        try:
            with socket.create_connection((ip, porta), timeout=timeout):
                return True, time.monotonic() - inicio
        except ConnectionRefusedError:
            return True, time.monotonic() - inicio
        except OSError:
            continue
    return False, None


def nome_servico(porta):
    if porta in SERVICOS:
        return SERVICOS[porta]
    try:
        return socket.getservbyport(porta, "tcp")
    except OSError:
        return "desconhecido"


def resumir_banner(dados):
    """Extrai uma linha curta e legível do que o serviço respondeu."""
    if not dados:
        return None
    texto = dados.decode("latin-1", errors="replace")
    if texto.upper().startswith("HTTP/"):
        linhas = texto.splitlines()
        for linha in linhas:
            if linha.lower().startswith("server:"):
                return linha.split(":", 1)[1].strip()[:60] or None
        return linhas[0].strip()[:60]
    linhas = texto.strip().splitlines()
    if not linhas:
        return None
    limpo = "".join(c for c in linhas[0] if 32 <= ord(c) < 127)
    return limpo[:60] or None


def capturar_banner(sock, ip, porta, timeout):
    """Lê o que o serviço diz ao conectar (SSH, FTP, SMTP...) ou, em portas
    web, pergunta com um HEAD e lê o cabeçalho Server."""
    sock.settimeout(min(max(timeout, 0.5), 2.0))
    conexao = sock
    try:
        if porta in PORTAS_TLS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conexao = ctx.wrap_socket(sock)
        sonda = ("HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: scarface\r\n\r\n" % ip).encode()
        if porta in PORTAS_HTTP or porta in PORTAS_TLS:
            conexao.sendall(sonda)
            dados = conexao.recv(1024)
        else:
            # serviços como SSH/FTP/SMTP falam primeiro; se a porta ficar
            # calada, pode ser um servidor web em porta não padrão: sonda com HEAD
            try:
                dados = conexao.recv(1024)
            except socket.timeout:
                conexao.sendall(sonda)
                dados = conexao.recv(1024)
    except OSError:  # inclui timeout e erros de TLS
        return None
    finally:
        if conexao is not sock:
            conexao.close()
    return resumir_banner(dados)


def escanear_porta(ip, porta, timeout, banner):
    """Tenta conectar. Retorna (porta, estado, banner).

    aberta   -> a conexão foi aceita
    fechada  -> o host recusou (RST): tem alguém lá, mas nada escutando
    filtrada -> sem resposta / bloqueada (firewall)
    """
    try:
        s = socket.create_connection((ip, porta), timeout=timeout)
    except ConnectionRefusedError:
        return porta, "fechada", None
    except OSError:
        return porta, "filtrada", None
    try:
        info = capturar_banner(s, ip, porta, timeout) if banner else None
    finally:
        s.close()
    return porta, "aberta", info


def escanear_host(ip, portas, timeout, threads, banner):
    abertas, fechadas, filtradas = [], 0, 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futuros = [pool.submit(escanear_porta, ip, p, timeout, banner) for p in portas]
        try:
            for f in as_completed(futuros):
                porta, estado, info = f.result()
                if estado == "aberta":
                    abertas.append({"porta": porta, "servico": nome_servico(porta),
                                    "banner": info})
                elif estado == "fechada":
                    fechadas += 1
                else:
                    filtradas += 1
        except KeyboardInterrupt:
            for f in futuros:
                f.cancel()
            raise
    abertas.sort(key=lambda a: a["porta"])
    return abertas, fechadas, filtradas


# ------------------------------------------------------------------
# SAÍDA
# ------------------------------------------------------------------

def imprimir_host(res, cores):
    nome, ip = res["host"], res["ip"]
    titulo = ip if nome == ip else f"{nome} ({ip})"
    print(pintar(f"Relatório de scan para {titulo}", "negrito", cores))

    if res["latencia_ms"] is None:
        print("Host assumido como ativo (-Pn).")
    else:
        print(f"Host ativo ({res['latencia_ms'] / 1000:.4f}s de latência).")

    ocultas = res["fechadas"] + res["filtradas"]
    if ocultas:
        print(f"Não mostradas: {res['fechadas']} fechada(s), {res['filtradas']} filtrada(s).")

    if not res["abertas"]:
        print("Nenhuma porta aberta encontrada.\n")
        return

    mostrar_versao = any(a["banner"] for a in res["abertas"])
    cab = f"{'PORTA':<10}{'ESTADO':<10}{'SERVIÇO':<16}" + ("VERSÃO/BANNER" if mostrar_versao else "")
    print(pintar(cab.rstrip(), "ciano", cores))
    for a in res["abertas"]:
        linha_porta = f"{str(a['porta']) + '/tcp':<10}"
        estado = pintar(f"{'aberta':<10}", "verde", cores)
        print(f"{linha_porta}{estado}{a['servico']:<16}{a['banner'] or ''}".rstrip())
    print()


# ------------------------------------------------------------------
# ARGUMENTOS
# ------------------------------------------------------------------

def inteiro_positivo(valor):
    try:
        n = int(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{valor}' não é um inteiro válido")
    if n <= 0:
        raise argparse.ArgumentTypeError(f"'{valor}' deve ser maior que zero")
    return n


def decimal_positivo(valor):
    try:
        n = float(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{valor}' não é um número válido")
    if n <= 0:
        raise argparse.ArgumentTypeError(f"'{valor}' deve ser maior que zero")
    return n


def criar_parser():
    parser = argparse.ArgumentParser(
        prog="scarface",
        description="Scanner de portas TCP simples, inspirado no nmap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Exemplos:\n"
                "  scarface 192.168.0.1\n"
                "  scarface scanme.nmap.org -p 22,80,443 -sV\n"
                "  scarface 192.168.0.0/24 -F\n"
                "  scarface 10.0.0.5 -p- -t 300 -o resultado.json\n\n"
                "Use apenas em sistemas seus ou com autorização explícita."),
    )
    parser.add_argument("alvos", nargs="+", metavar="alvo",
                        help="IP, nome de host ou faixa CIDR (pode informar vários)")
    parser.add_argument("-p", "--portas", default="1-1024",
                        help="portas: '80', '22,80,443', '1-1000' ou '-' para todas "
                             "(padrão: 1-1024)")
    parser.add_argument("-F", "--rapido", action="store_true",
                        help="escaneia só as portas mais comuns")
    parser.add_argument("-sV", "--banner", action="store_true",
                        help="tenta identificar a versão/banner dos serviços abertos")
    parser.add_argument("-Pn", "--sem-ping", action="store_true",
                        help="não checa se o host está ativo; escaneia direto")
    parser.add_argument("-t", "--threads", type=inteiro_positivo, default=100,
                        help="conexões simultâneas (padrão: 100)")
    parser.add_argument("-T", "--timeout", type=decimal_positivo, default=1.0,
                        help="tempo máximo por porta, em segundos (padrão: 1.0)")
    parser.add_argument("-o", "--saida", metavar="ARQUIVO.json",
                        help="salva o resultado em JSON")
    parser.add_argument("--sem-cor", action="store_true", help="desativa as cores")
    parser.add_argument("--versao", action="version", version=f"SCARFACE {VERSION}")
    return parser


# ------------------------------------------------------------------
# PRINCIPAL
# ------------------------------------------------------------------

def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

    parser = criar_parser()
    args = parser.parse_args()

    if args.threads > 1000:
        parser.error("--threads no máximo 1000 (mais que isso costuma estourar o limite de arquivos abertos)")

    try:
        portas = TOP_PORTAS if args.rapido else parse_portas(args.portas)
    except ValueError as e:
        parser.error(f"portas inválidas: {e}")
    try:
        alvos = expandir_alvos(args.alvos)
    except ValueError as e:
        parser.error(str(e))

    if args.saida:
        pasta = os.path.dirname(os.path.abspath(args.saida))
        if not os.path.isdir(pasta) or not os.access(pasta, os.W_OK):
            parser.error(f"não consigo gravar em: {pasta}")

    cores = (not args.sem_cor) and terminal_suporta_cor()
    print(pintar(BANNER, "ciano", cores))
    print(f"\nIniciando SCARFACE {VERSION} em {datetime.now():%Y-%m-%d %H:%M:%S} | "
          f"{len(alvos)} host(s), {len(portas)} porta(s) cada\n")

    inicio = time.monotonic()

    # 1. descoberta de hosts
    if args.sem_ping:
        ativos = [(n, ip, None) for n, ip in alvos]
    else:
        ativos = []
        with ThreadPoolExecutor(max_workers=min(args.threads, len(alvos))) as pool:
            futuros = {pool.submit(host_ativo, ip, args.timeout): (n, ip) for n, ip in alvos}
            resultados = {}
            for f in as_completed(futuros):
                resultados[futuros[f]] = f.result()
        for n, ip in alvos:  # mantém a ordem original
            ok, lat = resultados[(n, ip)]
            if ok:
                ativos.append((n, ip, lat))

    if not ativos:
        print("Nenhum host ativo encontrado.")
        if len(alvos) == 1:
            print("Se o host realmente estiver ligado mas bloqueando as sondagens, tente -Pn.")
        return 1

    # 2. escaneamento de portas, host por host
    todos = []
    for nome, ip, lat in ativos:
        abertas, fechadas, filtradas = escanear_host(
            ip, portas, args.timeout, args.threads, args.banner)
        res = {"host": nome, "ip": ip,
               "latencia_ms": round(lat * 1000, 2) if lat is not None else None,
               "abertas": abertas, "fechadas": fechadas, "filtradas": filtradas}
        todos.append(res)
        imprimir_host(res, cores)

    duracao = time.monotonic() - inicio
    print(f"Concluído: {len(alvos)} host(s) verificado(s), {len(ativos)} ativo(s), "
          f"em {duracao:.2f} segundos.")

    if args.saida:
        dados = {"ferramenta": f"SCARFACE {VERSION}",
                 "data": datetime.now().isoformat(timespec="seconds"),
                 "duracao_segundos": round(duracao, 2),
                 "portas_escaneadas": len(portas),
                 "hosts": todos}
        try:
            with open(args.saida, "w", encoding="utf-8") as f:
                json.dump(dados, f, ensure_ascii=False, indent=2)
        except OSError as e:
            parser.error(f"não consegui salvar '{args.saida}': {e}")
        print(f"Resultado salvo em {args.saida}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário (Ctrl+C).")
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
