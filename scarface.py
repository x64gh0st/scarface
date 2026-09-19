#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SCARFACE - Systematic Cyber Attack Recognition and Forensic Analysis
          of Critical Events
===========================================================================

Analisador de logs que caça sinais de ataque:

  [1] BRUTE FORCE ........... muitas falhas de login vindas do mesmo IP
                              dentro de uma janela de tempo curta.
  [2] COMPROMETIMENTO ....... o mesmo IP que falhou o login várias vezes
                              e DEPOIS acertou (conta possivelmente invadida).
  [3] ESCANEAMENTO .......... rajada de respostas 404 (alguém procurando
                              diretórios, backups, painéis de admin...).
  [4] ATAQUES EM URL ........ SQL Injection, XSS e Path Traversal
                              escondidos nos pedidos HTTP.

Formatos suportados:
  auto ............. detecta sozinho (padrão)
  auth ............. /var/log/auth.log do Linux (sshd)
  apache ........... logs de acesso HTTP (access.log)
  geral ............ qualquer log com endereços IP

Exemplos:
  python scarface.py auth.log
  python scarface.py access.log --saida relatorio.md --json dados.json
  python scarface.py auth.log --limite 3 --janela 60 --sem-cor
  python scarface.py --demo

Créditos:
  by DevPedroHenrique
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

VERSION = "1.0.0"

# ------------------------------------------------------------------
# 1. CONFIGURAÇÃO
# ------------------------------------------------------------------

# Palavras-chave que identificam FALHA ou SUCESSO nos logs de autenticação
EVENTOS_FALHA = {"failed password", "invalid user", "authentication failure"}
EVENTOS_SUCESSO = ("accepted",)

LIMITE_FALHAS = 5      # falhas suficientes para virar alerta de brute force
JANELA_PADRAO = 300    # janela de tempo (segundos) usada no brute force
LIMITE_404 = 10        # 404 suficientes para virar alerta de escaneamento

# Expressões regulares dos formatos de log suportados.
#
# auth:   Sep 17 09:14:22 srv sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
REG_SSH = re.compile(
    r"^(?P<data>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<evento>Failed password|Invalid user|Accepted\s+\w+)"
    r"(?:(?:\s+for\s+)?(?:invalid user\s+)?(?P<usuario>\S+))?"
    r"(?:\s+from\s+(?P<ip>\S+))?",
    re.IGNORECASE,
)

# apache: 203.0.113.7 - - [17/Sep/2026:09:14:22 +0000] "GET /wp-login.php HTTP/1.1" 200 1234 "-" "UA"
REG_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<data>[^\]]+)\]\s+"(?P<requisicao>[^"]*)"\s+'
    r"(?P<status>\d{3})(?:\s+\S+)?"
)

# geral: qualquer linha que contenha um IPv4
REG_IP_GERAL = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")

# Padrões de ataque procurados dentro das URLs (assinaturas conhecidas)
PADROES_ATAQUE = [
    ("SQL Injection", re.compile(
        r"(\bunion\b.*\bselect\b|'\s*(or|and)\b|--\s|/\*|information_schema|sleep\s*\()", re.I)),
    ("XSS", re.compile(
        r"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|alert\s*\()", re.I)),
    ("Path Traversal", re.compile(
        r"(\.\./|\.\.\\|\.\.%2[fF]|%2e%2e)", re.I)),
    ("Command Injection", re.compile(
        r"(;\s*(cat|ls|whoami|id|nc|wget|curl|bash|sh)\b|[|&]\s*(cat|ls|whoami|id|bash|sh)\b)", re.I)),
]

# ------------------------------------------------------------------
# 2. UTILITÁRIOS
# ------------------------------------------------------------------

CORES = {
    "vermelho": "\033[91m", "verde": "\033[92m", "amarelo": "\033[93m",
    "ciano": "\033[96m", "negrito": "\033[1m", "fim": "\033[0m",
}


BANNER = """\
  ███████╗ ██████╗ █████╗ ██████╗ ███████╗ █████╗  ██████╗███████╗
  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
  ███████╗██║     ███████║██████╔╝█████╗  ███████║██║     █████╗
  ╚════██║██║     ██╔══██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝
  ███████║╚██████╗██║  ██║██║  ██║██║     ██║  ██║╚██████╗███████╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
  Systematic Cyber Attack Recognition and Forensic Analysis
  of Critical Events
  by DevPedroHenrique"""


def pintar(texto, estilo, ativo=True):
    """Aplica cor/negrito ANSI somente quando o terminal suportar."""
    if not ativo or estilo not in CORES:
        return texto
    return CORES[estilo] + texto + CORES["fim"]


def parsear_data_ssh(texto):
    """Converte 'Sep 17 09:14:22' em datetime (o ano é inferido)."""
    agora = datetime.now()
    for ano in (agora.year, agora.year - 1):  # logs costumam ser do ano atual ou anterior
        try:
            dt = datetime.strptime(f"{texto} {ano}", "%b %d %H:%M:%S %Y")
            break
        except ValueError:
            continue
    else:
        return None
    if dt > agora + timedelta(days=1):  # log do ano passado
        dt = dt.replace(year=dt.year - 1)
    return dt.replace(tzinfo=timezone.utc)


def parsear_data_apache(texto):
    """Converte '17/Sep/2026:09:14:22 +0000' em datetime."""
    try:
        return datetime.strptime(texto, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def janela_deslizante(tempos, janela):
    """Maior quantidade de eventos dentro de qualquer intervalo de 'janela'
    segundos. Retorna (quantidade, indice_inicio, indice_fim).

    Técnica clássica de dois ponteiros: para cada fim da lista, avançamos
    o início até o intervalo caber na janela. Vai de O(n) em vez de O(n^2).
    """
    melhor = (0, 0, -1)
    inicio = 0
    for fim in range(len(tempos)):
        while tempos[fim] - tempos[inicio] > timedelta(seconds=janela):
            inicio += 1
        if fim - inicio + 1 > melhor[0]:
            melhor = (fim - inicio + 1, inicio, fim)
    return melhor


def novo_registro(ip=None, data=None, usuario=None, evento=None,
                  status=None, caminho=None, tipo="info", bruto=""):
    """Cria um registro estruturado (dict) a partir de uma linha do log.

    tipo pode ser: 'falha' | 'sucesso' | 'info' | 'ignorada'
    """
    return {"ip": ip, "data": data, "usuario": usuario, "evento": evento,
            "status": status, "caminho": caminho, "tipo": tipo, "bruto": bruto}


# ------------------------------------------------------------------
# 3. PARSING DOS LOGS
# ------------------------------------------------------------------

def detectar_formato(linhas):
    """Amostra as primeiras linhas e decide qual formato encaixa melhor."""
    amostra = [l for l in linhas[:50] if l.strip()]
    ssh = sum(1 for l in amostra if REG_SSH.match(l))
    apache = sum(1 for l in amostra if REG_APACHE.match(l))
    if ssh >= apache and ssh > 0:
        return "auth"
    if apache > 0:
        return "apache"
    return "geral"


def parsear_linhas(linhas, formato):
    """Transforma cada linha do log em um registro estruturado."""
    registros = []
    for linha in linhas:
        linha = linha.rstrip("\n")
        if not linha.strip():
            continue

        if formato == "auth":
            m = REG_SSH.match(linha)
            if not m:
                registros.append(novo_registro(tipo="ignorada", bruto=linha))
                continue
            evento = m.group("evento").lower()
            if any(e in evento for e in EVENTOS_FALHA):
                tipo = "falha"
            elif evento.startswith(EVENTOS_SUCESSO):
                tipo = "sucesso"
            else:
                tipo = "info"
            registros.append(novo_registro(
                ip=m.group("ip"), data=parsear_data_ssh(m.group("data")),
                usuario=(m.group("usuario") or "").lower(), evento=evento,
                tipo=tipo, bruto=linha))

        elif formato == "apache":
            m = REG_APACHE.match(linha)
            if not m:
                registros.append(novo_registro(tipo="ignorada", bruto=linha))
                continue
            requisicao = m.group("requisicao")
            partes = requisicao.split()
            metodo, caminho = (partes[0], partes[1]) if len(partes) > 1 else ("", requisicao)
            registros.append(novo_registro(
                ip=m.group("ip"), data=parsear_data_apache(m.group("data")),
                evento=metodo, status=int(m.group("status")), caminho=caminho,
                tipo="info", bruto=linha))

        else:  # geral: só extrai o IP da linha
            m = REG_IP_GERAL.search(linha)
            registros.append(novo_registro(
                ip=m.group("ip") if m else None, evento="linha", tipo="info", bruto=linha))

    return registros


# ------------------------------------------------------------------
# 4. DETECÇÕES
# ------------------------------------------------------------------

def detectar_brute_force(registros, limite=LIMITE_FALHAS, janela=JANELA_PADRAO):
    """Falhas de login agrupadas por IP; a janela deslizante acha as rajadas."""
    alertas = []
    por_ip = defaultdict(list)
    for r in registros:
        if r["tipo"] == "falha" and r["ip"] and r["data"]:
            por_ip[r["ip"]].append((r["data"], r["usuario"]))

    for ip, ocorrencias in por_ip.items():
        ocorrencias.sort(key=lambda o: o[0])
        tempos = [o[0] for o in ocorrencias]
        if janela and janela > 0:
            maximo, ini, fim = janela_deslizante(tempos, janela)
        else:
            maximo, ini, fim = len(tempos), 0, len(tempos) - 1
        if maximo >= limite:
            alvos = Counter(o[1] for o in ocorrencias[ini:fim + 1])
            alertas.append({
                "ip": ip,
                "total_falhas": len(ocorrencias),
                "falhas_na_janela": maximo,
                "janela_segundos": janela,
                "inicio": tempos[ini].isoformat(),
                "fim": tempos[fim].isoformat(),
                "alvo_mais_visado": alvos.most_common(1)[0] if alvos else None,
            })
    alertas.sort(key=lambda a: a["falhas_na_janela"], reverse=True)
    return alertas


def detectar_comprometimento(registros):
    """IP que falhou várias vezes e depois conseguiu logar: sinal vermelho."""
    alertas = []
    por_ip = defaultdict(list)
    for r in registros:
        if r["ip"] and r["data"] and r["tipo"] in ("falha", "sucesso"):
            por_ip[r["ip"]].append(r)

    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda e: e["data"])
        falhas = [e for e in eventos if e["tipo"] == "falha"]
        sucessos = [e for e in eventos if e["tipo"] == "sucesso"]
        if falhas and sucessos and sucessos[0]["data"] >= falhas[0]["data"]:
            alertas.append({
                "ip": ip,
                "falhas_anteriores": len(falhas),
                "usuario": sucessos[0]["usuario"],
                "data_primeira_falha": falhas[0]["data"].isoformat(),
                "data_sucesso": sucessos[0]["data"].isoformat(),
            })
    return alertas


def detectar_escaneamento(registros, limite=LIMITE_404):
    """Muitos 404 do mesmo IP = alguém fuçando o servidor (enumeração)."""
    alertas = []
    por_ip = defaultdict(Counter)
    for r in registros:
        if r["status"] == 404 and r["ip"]:
            por_ip[r["ip"]][r["caminho"]] += 1
    for ip, caminhos in por_ip.items():
        total = sum(caminhos.values())
        if total >= limite:
            alertas.append({
                "ip": ip,
                "total_404": total,
                "caminhos_distintos": len(caminhos),
                "exemplos": caminhos.most_common(3),
            })
    alertas.sort(key=lambda a: a["total_404"], reverse=True)
    return alertas


def detectar_ataques(registros):
    """Procura assinaturas de ataque conhecidas dentro das URLs."""
    contagem = Counter()
    amostras = {}
    for r in registros:
        alvo = r["caminho"]
        if not alvo:
            continue
        for nome, padrao in PADROES_ATAQUE:
            if padrao.search(alvo):
                chave = (r["ip"], nome)
                contagem[chave] += 1
                amostras.setdefault(chave, alvo)
    return [{"ip": ip, "tipo": nome, "ocorrencias": n, "exemplo": amostras[(ip, nome)]}
            for (ip, nome), n in contagem.most_common()]


# ------------------------------------------------------------------
# 5. RELATÓRIOS
# ------------------------------------------------------------------

def _truncar(texto, tamanho=90):
    """Encurta strings longas (ex.: URLs) para exibição no terminal."""
    if texto and len(texto) > tamanho:
        return texto[:tamanho] + "..."
    return texto


def exibir_console(info, cores=True):
    negrito = lambda t: pintar(t, "negrito", cores)
    vermelho = lambda t: pintar(t, "vermelho", cores)
    verde = lambda t: pintar(t, "verde", cores)
    amarelo = lambda t: pintar(t, "amarelo", cores)
    ciano = lambda t: pintar(t, "ciano", cores)

    print()
    print(ciano(BANNER))
    print()
    print(f"  Arquivo    : {info['arquivo']}")
    print(f"  Formato    : {info['formato']} ({info['fonte_formato']})")
    print(f"  Linhas     : {info['totais']['total']} lidas, "
          f"{info['totais']['interpretadas']} interpretadas, "
          f"{info['totais']['ignoradas']} ignoradas")
    print()
    print(negrito("  [ RESUMO ]"))
    print(f"  + Brute force     : {len(info['brute_force'])} IP(s)")
    print(f"  + Comprometimento : {len(info['comprometimentos'])} IP(s)")
    print(f"  + Escaneamento    : {len(info['escaneamento'])} IP(s)")
    print(f"  + Ataques em URL  : {sum(a['ocorrencias'] for a in info['ataques'])} ocorrência(s)")
    print()

    if info["brute_force"]:
        print(vermelho(negrito("  [!] ALERTA - BRUTE FORCE")))
        for b in info["brute_force"]:
            print(f"  IP ....................: {b['ip']}")
            print(f"  Falhas totais .........: {b['total_falhas']}")
            print(f"  Falhas na janela ......: {b['falhas_na_janela']} "
                  f"({b['janela_segundos']} s)")
            if b["alvo_mais_visado"]:
                print(f"  Alvo mais visado ......: {b['alvo_mais_visado'][0]} "
                      f"({b['alvo_mais_visado'][1]}x)")
            print(f"  Período ...............: {b['inicio']} ate {b['fim']}")
            print()
    else:
        print(verde("  [x] Nenhum sinal de brute force"))
        print()

    if info["comprometimentos"]:
        print(vermelho(negrito("  [!] ALERTA - COMPROMETIMENTO EM ANDAMENTO")))
        for c in info["comprometimentos"]:
            print(f"  IP .....................: {c['ip']}")
            print(f"  Falhas anteriores ......: {c['falhas_anteriores']}")
            print(f"  Login bem-sucedido .....: {c['usuario']} em {c['data_sucesso']}")
            print()
    else:
        print(verde("  [x] Nenhum sinal de comprometimento"))
        print()

    if info["escaneamento"]:
        print(amarelo(negrito("  [!] ALERTA - ESCANEAMENTO (rajada de 404)")))
        for e in info["escaneamento"]:
            print(f"  IP .....................: {e['ip']}")
            print(f"  Total de 404 ...........: {e['total_404']}")
            print(f"  Caminhos distintos .....: {e['caminhos_distintos']}")
            for caminho, n in e["exemplos"]:
                print(f"    - {_truncar(caminho)} ({n}x)")
            print()
    else:
        print(verde("  [x] Nenhum sinal de escaneamento"))
        print()

    if info["ataques"]:
        print(amarelo(negrito("  [!] ALERTA - ATAQUES NAS URLs")))
        for a in info["ataques"]:
            print(f"  {a['tipo']} | {a['ip']} | {a['ocorrencias']}x")
            print(f"    exemplo: {_truncar(a['exemplo'])}")
        print()
    else:
        print(verde("  [x] Nenhuma assinatura de ataque nas URLs"))
        print()

    if info["top_ips"]:
        print(negrito("  [ RESUMO DE ATIVIDADE ]"))
        print("  IPs mais ativos no log:")
        for posicao, (ip, n) in enumerate(info["top_ips"], 1):
            print(f"    {posicao}. {ip} - {n} evento(s)")
        print()


def salvar_markdown(info, caminho):
    """Gera um relatório legível em Markdown."""
    l = []
    a = l.append
    a("# SCARFACE - Relatório de análise de logs\n")
    a(f"Gerado por {info['ferramenta']} em {info['gerado_em']}\n")
    a("## Metadados")
    a("")
    a("| Campo | Valor |")
    a("|---|---|")
    a(f"| Arquivo | `{info['arquivo']}` |")
    a(f"| Formato | {info['formato']} ({info['fonte_formato']}) |")
    a(f"| Autor | DevPedroHenrique |")
    a(f"| Linhas totais | {info['totais']['total']} |")
    a(f"| Linhas interpretadas | {info['totais']['interpretadas']} |")
    a(f"| Linhas ignoradas | {info['totais']['ignoradas']} |")
    a("")
    a("## Resumo")
    a("")
    a(f"- Brute force: **{len(info['brute_force'])}** IP(s)")
    a(f"- Comprometimento: **{len(info['comprometimentos'])}** IP(s)")
    a(f"- Escaneamento: **{len(info['escaneamento'])}** IP(s)")
    a(f"- Ataques em URL: **{sum(x['ocorrencias'] for x in info['ataques'])}** ocorrência(s)")
    a("")

    if info["brute_force"]:
        a("## ALERTA - Brute force")
        a("")
        for b in info["brute_force"]:
            a(f"- IP: `{b['ip']}`")
            a(f"- Falhas totais: {b['total_falhas']}")
            a(f"- Falhas na janela ({b['janela_segundos']}s): {b['falhas_na_janela']}")
            if b["alvo_mais_visado"]:
                a(f"- Alvo mais visado: `{b['alvo_mais_visado'][0]}` ({b['alvo_mais_visado'][1]}x)")
            a(f"- Período: {b['inicio']} ate {b['fim']}")
            a("")

    if info["comprometimentos"]:
        a("## ALERTA - Comprometimento em andamento")
        a("")
        for c in info["comprometimentos"]:
            a(f"- IP: `{c['ip']}`")
            a(f"- Falhas anteriores: {c['falhas_anteriores']}")
            a(f"- Login bem-sucedido: `{c['usuario']}` em {c['data_sucesso']}")
            a("")

    if info["escaneamento"]:
        a("## ALERTA - Escaneamento (rajada de 404)")
        a("")
        for e in info["escaneamento"]:
            a(f"- IP: `{e['ip']}` - {e['total_404']} respostas 404 "
              f"({e['caminhos_distintos']} caminhos distintos)")
            for caminho_404, n in e["exemplos"]:
                a(f"  - `{caminho_404}` ({n}x)")
            a("")

    if info["ataques"]:
        a("## ALERTA - Ataques nas URLs")
        a("")
        a("| Tipo | IP | Ocorrências | Exemplo |")
        a("|---|---|---|---|")
        for at in info["ataques"]:
            exemplo = at["exemplo"].replace("|", "\\|")
            a(f"| {at['tipo']} | `{at['ip']}` | {at['ocorrencias']} | `{exemplo}` |")
        a("")

    if info["top_ips"]:
        a("## IPs mais ativos")
        a("")
        a("| Posição | IP | Eventos |")
        a("|---|---|---|")
        for posicao, (ip, n) in enumerate(info["top_ips"], 1):
            a(f"| {posicao} | `{ip}` | {n} |")
        a("")

    with open(caminho, "w", encoding="utf-8") as f:
        f.write("\n".join(l))


def salvar_json(info, caminho):
    """Salva os resultados em JSON (fácil de integrar com outras ferramentas)."""
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------
# 6. DADOS DE DEMONSTRAÇÃO
# ------------------------------------------------------------------

def demo_auth():
    """Gera um /var/log/auth.log fictício para treinar sem perigo."""
    linhas = []
    pid = 1000

    # Atacante 1: força bruta contra root e admin (38 tentativas)
    for i in range(38):
        usuario = "root" if i % 2 == 0 else "admin"
        seg = (i * 7) % 60
        linhas.append(
            f"Sep 17 09:12:{seg:02d} srv-web sshd[{pid}]: "
            f"Failed password for {usuario} from 203.0.113.7 port {40000 + i} ssh2"
        )
        pid += 1

    # Atacante 2: falhou algumas vezes e DEPOIS acertou (comprometido)
    for i in range(6):
        linhas.append(
            f"Sep 17 10:0{i}:21 srv-web sshd[{pid}]: "
            f"Failed password for alice from 198.51.100.22 port {45000 + i} ssh2"
        )
        pid += 1
    linhas.append(
        f"Sep 17 10:07:45 srv-web sshd[{pid}]: "
        f"Accepted password for alice from 198.51.100.22 port 46123 ssh2"
    )
    pid += 1

    # Tráfego legítimo (acessos normais da equipe)
    for h, m, s in [("08", "30", "01"), ("13", "45", "12")]:
        linhas.append(
            f"Sep 17 {h}:{m}:{s} srv-web sshd[{pid}]: "
            f"Accepted password for carlos from 192.168.10.50 port 50022 ssh2"
        )
        pid += 1

    return linhas


def demo_apache():
    """Gera um access.log fictício para treinar sem perigo."""
    linhas = []

    # Escaneador: fuçando diretórios e arquivos sensíveis
    alvos = ["/admin", "/wp-login.php", "/backup", "/.git/config", "/phpmyadmin",
             "/config.php", "/server-status", "/.env", "/secret", "/db",
             "/log", "/uploads", "/shell.php", "/robots.txt.tmp"]
    for i, caminho in enumerate(alvos):
        linhas.append(
            f'203.0.113.7 - - [17/Sep/2026:09:{i // 60:02d}:{i % 60:02d}:14 +0000] '
            f'"GET {caminho} HTTP/1.1" 404 532 "-" "Mozilla/5.0 (X11)"'
        )

    # Atacante de aplicação: SQLi, XSS e path traversal
    payloads = [
        "/produto.php?id=1 OR 1=1",
        "/produto.php?id=1' OR '1'='1' -- -",
        "/busca.php?q=<script>alert(1)</script>",
        "/download.php?arquivo=../../etc/passwd",
        "/produto.php?id=1 UNION SELECT username,password FROM users",
        "/busca.php?q=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "/login.php?page=..%2f..%2f..%2fetc%2fpasswd",
    ]
    for i, caminho in enumerate(payloads):
        linhas.append(
            f'198.51.100.13 - - [17/Sep/2026:10:0{i}:05 +0000] '
            f'"GET {caminho} HTTP/1.1" 200 812 "https://loja.local/produto.php" '
            f'"sqlmap/1.7 (http://sqlmap.org)"'
        )

    # Tráfego normal
    for i in range(5):
        linhas.append(
            f'192.168.10.50 - - [17/Sep/2026:13:{i:02d}:00 +0000] '
            f'"GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (Windows NT 10.0)"'
        )

    return linhas


# ------------------------------------------------------------------
# 7. PONTO DE ENTRADA
# ------------------------------------------------------------------

def main():
    # Garante que acentos apareçam direito no terminal do Windows
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

    parser = argparse.ArgumentParser(
        prog="scarface",
        description="Analisador de logs - caça brute force, comprometimento, "
                    "escaneamento e ataques em URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python scarface.py auth.log\n"
            "  python scarface.py access.log --saida relatorio.md --json dados.json\n"
            "  python scarface.py --demo\n"
        ),
    )
    parser.add_argument("arquivo", nargs="?", help="caminho do arquivo de log")
    parser.add_argument("--demo", action="store_true",
                        help="analisa um log fictício de demonstração")
    parser.add_argument("--formato", choices=["auto", "auth", "apache", "geral"],
                        default="auto", help="formato do log (padrão: auto)")
    parser.add_argument("--limite", type=int, default=LIMITE_FALHAS,
                        help=f"falhas para alerta de brute force (padrão: {LIMITE_FALHAS})")
    parser.add_argument("--janela", type=int, default=JANELA_PADRAO,
                        help=f"janela de tempo em segundos (padrão: {JANELA_PADRAO})")
    parser.add_argument("--limite-404", dest="limite_404", type=int, default=LIMITE_404,
                        help=f"404 para alerta de escaneamento (padrão: {LIMITE_404})")
    parser.add_argument("--saida", help="salva relatório em Markdown neste arquivo")
    parser.add_argument("--json", dest="json_saida",
                        help="salva dados estruturados em JSON neste arquivo")
    parser.add_argument("--sem-cor", action="store_true",
                        help="desativa cores no terminal")
    parser.add_argument("--versao", action="version", version=f"SCARFACE {VERSION} by DevPedroHenrique")
    args = parser.parse_args()

    if not args.arquivo and not args.demo:
        parser.error("informe um arquivo de log ou use --demo")

    # 1. Carrega as linhas do log
    if args.demo:
        linhas = demo_auth()
        nome_arquivo, formato, fonte_formato = "(demonstração)", "auth", "demo"
    else:
        try:
            with open(args.arquivo, "r", encoding="utf-8", errors="replace") as f:
                linhas = f.readlines()
        except OSError as e:
            parser.error(f"não consegui ler o arquivo: {e}")
        nome_arquivo = args.arquivo

    # 2. Define o formato (detecção automática ou escolha manual)
    if args.formato == "auto":
        formato = detectar_formato(linhas)
        fonte_formato = "detectado"
    else:
        formato = args.formato
        fonte_formato = "informado"

    # 3. Interpreta as linhas
    registros = parsear_linhas(linhas, formato)

    # 4. Roda as detecções
    total = sum(1 for l in linhas if l.strip())
    interpretadas = sum(1 for r in registros if r["tipo"] != "ignorada")
    top_ips = Counter(r["ip"] for r in registros if r["ip"]).most_common(5)

    info = {
        "ferramenta": f"SCARFACE v{VERSION}",
        "autor": "DevPedroHenrique",
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "arquivo": nome_arquivo,
        "formato": formato,
        "fonte_formato": fonte_formato,
        "totais": {
            "total": total,
            "interpretadas": interpretadas,
            "ignoradas": total - interpretadas,
        },
        "brute_force": detectar_brute_force(registros, args.limite, args.janela),
        "comprometimentos": detectar_comprometimento(registros),
        "escaneamento": detectar_escaneamento(registros, args.limite_404),
        "ataques": detectar_ataques(registros),
        "top_ips": [(ip, n) for ip, n in top_ips],
    }

    # 5. Apresenta e salva os resultados
    usar_cores = (not args.sem_cor) and sys.stdout.isatty()
    exibir_console(info, cores=usar_cores)

    if args.saida:
        salvar_markdown(info, args.saida)
        print(f"  [*] Relatório Markdown salvo em {args.saida}")
    if args.json_saida:
        salvar_json(info, args.json_saida)
        print(f"  [*] Dados JSON salvos em {args.json_saida}")


if __name__ == "__main__":
    main()