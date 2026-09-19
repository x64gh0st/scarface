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
                              e DEPOIS acertou logo em seguida (conta
                              possivelmente invadida).
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
import os
import platform
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.1.0"

# ------------------------------------------------------------------
# 1. CONFIGURAÇÃO
# ------------------------------------------------------------------

# Palavras-chave que identificam FALHA ou SUCESSO nos logs de autenticação
EVENTOS_FALHA = {"failed password", "invalid user", "authentication failure"}
EVENTOS_SUCESSO = ("accepted",)

LIMITE_FALHAS = 5          # falhas suficientes para virar alerta de brute force
JANELA_PADRAO = 300        # janela de tempo (segundos) usada no brute force
LIMITE_404 = 10            # 404 suficientes para virar alerta de escaneamento
JANELA_COMPROMETIMENTO = 600  # segundos: sucesso precisa vir logo após as falhas

# Expressões regulares dos formatos de log suportados.
#
# auth: usamos DOIS regex específicos em vez de um só genérico, porque
# "Failed password"/"Accepted" e "Invalid user" têm estruturas de frase
# diferentes (o nome de usuário aparece em posições diferentes). Tentar
# capturar os dois casos com um regex único é o que causava usuário/IP
# trocados ou vazios em alguns logs reais.
#
#   Failed password for root from 1.2.3.4 port 22 ssh2
#   Accepted password for carlos from 192.168.10.50 port 50022 ssh2
REG_SSH_PADRAO = re.compile(
    r"^(?P<data>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<evento>Failed password|Accepted\s+\w+)\s+for\s+"
    r"(?P<usuario>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

#   Invalid user teste from 1.2.3.4 port 22
REG_SSH_INVALIDO = re.compile(
    r"^(?P<data>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<evento>Invalid user)\s+(?P<usuario>\S+)\s+from\s+(?P<ip>\S+)",
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


def habilitar_ansi_windows():
    """No Windows, o cmd.exe/PowerShell só interpretam códigos de cor ANSI
    se o modo de processamento de VT100 estiver ligado no console. Isso já
    vem ativo por padrão no Windows Terminal, mas não no console legado
    (cmd.exe clássico usado por versões mais antigas do Windows 10).

    Em Linux e macOS o terminal já suporta ANSI nativamente, então esta
    função não faz nada nesses sistemas.
    """
    if platform.system() != "Windows":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        modo = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(modo)):
            return False
        novo_modo = modo.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, novo_modo))
    except Exception:
        # Console mais antigo ou ambiente sem esse suporte: seguimos sem cor
        return False


def terminal_suporta_cor():
    """Decide se é seguro emitir códigos ANSI de cor neste terminal,
    de forma independente do sistema operacional."""
    if not sys.stdout.isatty():
        return False
    if platform.system() == "Windows":
        return habilitar_ansi_windows()
    return True


def parsear_data_ssh(texto, ano_referencia=None):
    """Converte 'Sep 17 09:14:22' em datetime (o ano é inferido).

    ano_referencia evita chamar datetime.now() repetidamente para cada
    linha do log (pequeno ganho de performance em arquivos grandes).
    """
    agora = datetime.now()
    ano_base = ano_referencia or agora.year
    for ano in (ano_base, ano_base - 1):
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
    ssh = sum(1 for l in amostra
              if REG_SSH_PADRAO.match(l) or REG_SSH_INVALIDO.match(l))
    apache = sum(1 for l in amostra if REG_APACHE.match(l))
    if ssh >= apache and ssh > 0:
        return "auth"
    if apache > 0:
        return "apache"
    return "geral"


def parsear_linhas(linhas, formato):
    """Transforma cada linha do log em um registro estruturado."""
    registros = []
    ano_referencia = datetime.now().year

    for linha in linhas:
        linha = linha.rstrip("\n")
        if not linha.strip():
            continue

        if formato == "auth":
            m = REG_SSH_PADRAO.match(linha) or REG_SSH_INVALIDO.match(linha)
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
                ip=m.group("ip"), data=parsear_data_ssh(m.group("data"), ano_referencia),
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


def detectar_comprometimento(registros, janela=JANELA_COMPROMETIMENTO,
                              minimo_falhas=3):
    """IP que falhou várias vezes e, LOGO DEPOIS (dentro de 'janela'
    segundos), conseguiu logar: sinal vermelho de conta comprometida.

    Antes, qualquer sucesso posterior a qualquer falha disparava o
    alerta, mesmo que fossem eventos sem relação (dias de distância).
    Agora exigimos:
      1) pelo menos 'minimo_falhas' falhas imediatamente antes do sucesso;
      2) o sucesso ocorrer dentro de 'janela' segundos após a última
         falha da sequência.
    """
    alertas = []
    por_ip = defaultdict(list)
    for r in registros:
        if r["ip"] and r["data"] and r["tipo"] in ("falha", "sucesso"):
            por_ip[r["ip"]].append(r)

    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda e: e["data"])
        falhas_seguidas = []
        for evento in eventos:
            if evento["tipo"] == "falha":
                falhas_seguidas.append(evento)
                continue

            # evento é um sucesso: verifica se veio logo após uma
            # sequência relevante de falhas
            if len(falhas_seguidas) >= minimo_falhas:
                ultima_falha = falhas_seguidas[-1]
                intervalo = (evento["data"] - ultima_falha["data"]).total_seconds()
                if 0 <= intervalo <= janela:
                    alertas.append({
                        "ip": ip,
                        "falhas_anteriores": len(falhas_seguidas),
                        "usuario": evento["usuario"],
                        "data_primeira_falha": falhas_seguidas[0]["data"].isoformat(),
                        "data_sucesso": evento["data"].isoformat(),
                        "intervalo_segundos": int(intervalo),
                    })
            # um login bem-sucedido (legítimo ou não) reinicia a contagem:
            # as falhas seguintes formam uma nova sequência
            falhas_seguidas = []
    alertas.sort(key=lambda a: a["falhas_anteriores"], reverse=True)
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

    safe_print()
    safe_print(ciano(BANNER))
    safe_print()
    safe_print(f"  Arquivo    : {info['arquivo']}")
    safe_print(f"  Formato    : {info['formato']} ({info['fonte_formato']})")
    safe_print(f"  Linhas     : {info['totais']['total']} lidas, "
          f"{info['totais']['interpretadas']} interpretadas, "
          f"{info['totais']['ignoradas']} ignoradas")
    safe_print()
    safe_print(negrito("  [ RESUMO ]"))
    safe_print(f"  + Brute force     : {len(info['brute_force'])} IP(s)")
    safe_print(f"  + Comprometimento : {len(info['comprometimentos'])} IP(s)")
    safe_print(f"  + Escaneamento    : {len(info['escaneamento'])} IP(s)")
    safe_print(f"  + Ataques em URL  : {sum(a['ocorrencias'] for a in info['ataques'])} ocorrência(s)")
    safe_print()

    if info["brute_force"]:
        safe_print(vermelho(negrito("  [!] ALERTA - BRUTE FORCE")))
        for b in info["brute_force"]:
            safe_print(f"  IP ....................: {b['ip']}")
            safe_print(f"  Falhas totais .........: {b['total_falhas']}")
            safe_print(f"  Falhas na janela ......: {b['falhas_na_janela']} "
                  f"({b['janela_segundos']} s)")
            if b["alvo_mais_visado"]:
                safe_print(f"  Alvo mais visado ......: {b['alvo_mais_visado'][0]} "
                      f"({b['alvo_mais_visado'][1]}x)")
            safe_print(f"  Período ...............: {b['inicio']} ate {b['fim']}")
            safe_print()
    else:
        safe_print(verde("  [x] Nenhum sinal de brute force"))
        safe_print()

    if info["comprometimentos"]:
        safe_print(vermelho(negrito("  [!] ALERTA - COMPROMETIMENTO EM ANDAMENTO")))
        for c in info["comprometimentos"]:
            safe_print(f"  IP .....................: {c['ip']}")
            safe_print(f"  Falhas imediatamente antes: {c['falhas_anteriores']}")
            safe_print(f"  Login bem-sucedido .....: {c['usuario']} em {c['data_sucesso']}")
            safe_print(f"  Intervalo falha->sucesso: {c['intervalo_segundos']}s")
            safe_print()
    else:
        safe_print(verde("  [x] Nenhum sinal de comprometimento"))
        safe_print()

    if info["escaneamento"]:
        safe_print(amarelo(negrito("  [!] ALERTA - ESCANEAMENTO (rajada de 404)")))
        for e in info["escaneamento"]:
            safe_print(f"  IP .....................: {e['ip']}")
            safe_print(f"  Total de 404 ...........: {e['total_404']}")
            safe_print(f"  Caminhos distintos .....: {e['caminhos_distintos']}")
            for caminho, n in e["exemplos"]:
                safe_print(f"    - {_truncar(caminho)} ({n}x)")
            safe_print()
    else:
        safe_print(verde("  [x] Nenhum sinal de escaneamento"))
        safe_print()

    if info["ataques"]:
        safe_print(amarelo(negrito("  [!] ALERTA - ATAQUES NAS URLs")))
        for a in info["ataques"]:
            safe_print(f"  {a['tipo']} | {a['ip']} | {a['ocorrencias']}x")
            safe_print(f"    exemplo: {_truncar(a['exemplo'])}")
        safe_print()
    else:
        safe_print(verde("  [x] Nenhuma assinatura de ataque nas URLs"))
        safe_print()

    if info["top_ips"]:
        safe_print(negrito("  [ RESUMO DE ATIVIDADE ]"))
        safe_print("  IPs mais ativos no log:")
        for posicao, (ip, n) in enumerate(info["top_ips"], 1):
            safe_print(f"    {posicao}. {ip} - {n} evento(s)")
        safe_print()


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
            a(f"- Falhas imediatamente antes: {c['falhas_anteriores']}")
            a(f"- Login bem-sucedido: `{c['usuario']}` em {c['data_sucesso']} "
              f"(intervalo de {c['intervalo_segundos']}s)")
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

    try:
        with open(caminho, "w", encoding="utf-8") as f:
            f.write("\n".join(l))
    except OSError as e:
        raise SystemExit(f"[erro] não consegui salvar o Markdown em '{caminho}': {e}")


def salvar_json(info, caminho):
    """Salva os resultados em JSON (fácil de integrar com outras ferramentas)."""
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(info, f, ensure_ascii=False, indent=2)
    except OSError as e:
        raise SystemExit(f"[erro] não consegui salvar o JSON em '{caminho}': {e}")


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

    # Atacante 2: falhou algumas vezes e DEPOIS acertou logo em seguida
    # (isso deve disparar o alerta de comprometimento)
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

    # Usuário inexistente tentando (Invalid user) - testa o segundo regex
    linhas.append(
        f"Sep 17 10:15:02 srv-web sshd[{pid}]: "
        f"Invalid user teste from 45.33.12.9 port 51000"
    )
    pid += 1

    # Tráfego legítimo: carlos loga bem sem nenhuma falha antes
    # (não deve disparar comprometimento - IP diferente, sem falhas)
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

def inteiro_positivo(valor):
    """Validador de argparse: exige um inteiro maior que zero.

    Sem isso, `--limite 0` faria QUALQUER IP disparar alerta de brute
    force (0 falhas >= 0 é sempre verdadeiro), e `--limite -5` teria o
    mesmo problema — a ferramenta "funcionaria" mas os alertas seriam
    inúteis, o que é pior do que travar com uma mensagem clara.
    """
    try:
        numero = int(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{valor}' não é um número inteiro válido")
    if numero <= 0:
        raise argparse.ArgumentTypeError(f"'{valor}' deve ser um número inteiro maior que zero")
    return numero


def inteiro_nao_negativo(valor):
    """Validador de argparse: exige um inteiro >= 0.

    Usado em `--janela`, onde 0 tem um significado válido (desativa a
    janela deslizante e conta todas as falhas do IP juntas).
    """
    try:
        numero = int(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{valor}' não é um número inteiro válido")
    if numero < 0:
        raise argparse.ArgumentTypeError(f"'{valor}' não pode ser negativo")
    return numero


def safe_print(texto=""):
    """print() que nunca derruba o programa por causa de um caractere
    que o console atual não sabe exibir.

    Isso pode acontecer com conteúdo vindo DIRETO do log do usuário
    (uma URL ou usuário com caractere estranho) sendo impresso num
    console com codificação limitada (ex.: cmd.exe em cp437). Em vez
    de um traceback no meio do relatório, substituímos o caractere
    problemático e seguimos em frente.
    """
    try:
        print(texto)
    except UnicodeEncodeError:
        codificacao = sys.stdout.encoding or "utf-8"
        print(texto.encode(codificacao, errors="replace").decode(codificacao, errors="replace"))


def validar_caminho_saida(caminho, parser):
    """Confere, ANTES de rodar toda a análise, se dá pra escrever no
    caminho pedido (--saida / --json). Evita descobrir só no final,
    depois de processar um log gigante, que a pasta não existe ou
    não tem permissão de escrita."""
    caminho = Path(caminho)
    pasta = caminho.parent if str(caminho.parent) else Path(".")
    if not pasta.exists():
        parser.error(f"a pasta de destino não existe: {pasta}")
    if pasta.is_dir() and not os.access(pasta, os.W_OK):
        parser.error(f"sem permissão de escrita em: {pasta}")


def ler_log(caminho, parser):
    """Lê o arquivo de log de forma tolerante a diferenças de encoding
    entre sistemas operacionais.

    - Linux/macOS costumam gravar logs em UTF-8.
    - Windows às vezes usa cp1252/latin-1 (ex.: logs exportados de
      ferramentas locais, ou copiados de outra máquina).

    Tentamos UTF-8 primeiro; se falhar, caímos para latin-1, que nunca
    lança erro de decodificação (mapeia byte a byte) — assim o usuário
    nunca é bloqueado por um caractere estranho no meio do log.
    """
    caminho = Path(caminho)
    if not caminho.exists():
        parser.error(f"arquivo não encontrado: {caminho}")
    if caminho.is_dir():
        parser.error(f"o caminho informado é uma pasta, não um arquivo: {caminho}")
    try:
        if caminho.stat().st_size == 0:
            parser.error(f"o arquivo está vazio: {caminho}")
    except OSError as e:
        parser.error(f"não consegui acessar o arquivo: {e}")

    for codificacao in ("utf-8", "latin-1"):
        try:
            with open(caminho, "r", encoding=codificacao, errors="strict") as f:
                return f.readlines()
        except UnicodeDecodeError:
            continue
        except PermissionError:
            parser.error(f"sem permissão de leitura: {caminho}")
        except OSError as e:
            parser.error(f"não consegui ler o arquivo: {e}")
    # não deveria chegar aqui (latin-1 não falha), mas por segurança:
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


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
    parser.add_argument("--demo-tipo", choices=["auth", "apache"], default="auth",
                        help="qual log fictício usar com --demo: 'auth' (SSH, padrão) "
                             "ou 'apache' (HTTP, mostra escaneamento e ataques em URL)")
    parser.add_argument("--formato", choices=["auto", "auth", "apache", "geral"],
                        default="auto", help="formato do log (padrão: auto)")
    parser.add_argument("--limite", type=inteiro_positivo, default=LIMITE_FALHAS,
                        help=f"falhas para alerta de brute force (padrão: {LIMITE_FALHAS})")
    parser.add_argument("--janela", type=inteiro_nao_negativo, default=JANELA_PADRAO,
                        help=f"janela de tempo em segundos (padrão: {JANELA_PADRAO})")
    parser.add_argument("--limite-404", dest="limite_404", type=inteiro_positivo, default=LIMITE_404,
                        help=f"404 para alerta de escaneamento (padrão: {LIMITE_404})")
    parser.add_argument("--janela-comprometimento", dest="janela_comprometimento",
                        type=inteiro_positivo, default=JANELA_COMPROMETIMENTO,
                        help="segundos entre a última falha e o sucesso para "
                             f"considerar comprometimento (padrão: {JANELA_COMPROMETIMENTO})")
    parser.add_argument("--saida", help="salva relatório em Markdown neste arquivo")
    parser.add_argument("--json", dest="json_saida",
                        help="salva dados estruturados em JSON neste arquivo")
    parser.add_argument("--sem-cor", action="store_true",
                        help="desativa cores no terminal")
    parser.add_argument("--versao", action="version", version=f"SCARFACE {VERSION} by DevPedroHenrique")
    args = parser.parse_args()

    if not args.arquivo and not args.demo:
        parser.error("informe um arquivo de log ou use --demo")

    # Valida os caminhos de saída ANTES de processar o log inteiro —
    # evita gastar tempo com um arquivo gigante só pra descobrir no
    # final que a pasta de destino não existe ou está sem permissão.
    if args.saida:
        validar_caminho_saida(args.saida, parser)
    if args.json_saida:
        validar_caminho_saida(args.json_saida, parser)

    # 1. Carrega as linhas do log
    if args.demo:
        if args.demo_tipo == "apache":
            linhas = demo_apache()
            nome_arquivo, formato, fonte_formato = "(demonstração HTTP)", "apache", "demo"
        else:
            linhas = demo_auth()
            nome_arquivo, formato, fonte_formato = "(demonstração)", "auth", "demo"
    else:
        linhas = ler_log(args.arquivo, parser)
        nome_arquivo = args.arquivo

    # 2. Define o formato (detecção automática ou escolha manual).
    # No modo --demo o formato já é conhecido (view acima), então só
    # detectamos/aplicamos --formato quando um arquivo real foi informado.
    if not args.demo:
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
        "comprometimentos": detectar_comprometimento(registros, args.janela_comprometimento),
        "escaneamento": detectar_escaneamento(registros, args.limite_404),
        "ataques": detectar_ataques(registros),
        "top_ips": [(ip, n) for ip, n in top_ips],
    }

    # 5. Apresenta e salva os resultados
    usar_cores = (not args.sem_cor) and terminal_suporta_cor()
    exibir_console(info, cores=usar_cores)

    if args.saida:
        salvar_markdown(info, args.saida)
        print(f"  [*] Relatório Markdown salvo em {args.saida}")
    if args.json_saida:
        salvar_json(info, args.json_saida)
        print(f"  [*] Dados JSON salvos em {args.json_saida}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  [!] Interrompido pelo usuário (Ctrl+C).")
        sys.exit(130)
    except BrokenPipeError:
        # Acontece quando a saída é cortada no meio, ex.: `scarface.py log | head`
        # ou o terminal é fechado durante a impressão. Não é um erro real da
        # ferramenta, então saímos em silêncio em vez de mostrar um traceback.
        sys.exit(0)
    except SystemExit:
        # gerado por parser.error(), --versao, --help etc.: já tratado,
        # só deixamos propagar com o código de saída correto.
        raise
    except Exception as e:
        # Última linha de defesa: qualquer erro inesperado (log corrompido
        # de um jeito não previsto, disco cheio ao salvar, etc.) vira uma
        # mensagem legível em vez de um traceback assustador para quem
        # for avaliar a ferramenta.
        try:
            print(f"\n  [erro inesperado] {type(e).__name__}: {e}")
            print("  Se achar que isso é um bug, abra uma issue no repositório do projeto.")
        except BrokenPipeError:
            pass
        sys.exit(1)
