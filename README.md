# 🔪 SCARFACE

**S**ystematic **C**yber **A**ttack **R**ecognition and **F**orensic **A**nalysis of **C**ritical **E**vents

[![Testes](https://github.com/x64gh0st/scarface/actions/workflows/tests.yml/badge.svg)](https://github.com/x64gh0st/scarface/actions/workflows/tests.yml)

Ferramenta de linha de comando em Python para análise forense de logs, feita para identificar rapidamente sinais de ataque em servidores Linux (SSH) e aplicações web (Apache/Nginx/JSON estruturado). Funciona em Windows, macOS e qualquer distro Linux, sem dependências externas.

```
  ███████╗ ██████╗ █████╗ ██████╗ ███████╗ █████╗  ██████╗███████╗
  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
  ███████╗██║     ███████║██████╔╝█████╗  ███████║██║     █████╗
  ╚════██║██║     ██╔══██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝
  ███████║╚██████╗██║  ██║██║  ██║██║     ██║  ██║╚██████╗███████╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
```

## O que ele detecta

| # | Ameaça | Como é identificada |
|---|--------|----------------------|
| 1 | **Brute Force** | Muitas falhas de login vindas do mesmo IP dentro de uma janela de tempo curta (algoritmo de janela deslizante, O(n)) |
| 2 | **Brute Force distribuído** | Vários IPs diferentes tentando o mesmo usuário na mesma janela (técnica pra escapar de bloqueios por IP único) |
| 3 | **Comprometimento** | Um IP que falhou o login várias vezes *seguidas* e, logo em seguida (dentro de uma janela configurável), conseguiu acertar (indício de conta invadida) |
| 4 | **Escaneamento** | Rajada de respostas HTTP 404 do mesmo IP (alguém procurando diretórios, backups, painéis de admin) |
| 5 | **Ataques em URL** | Assinaturas de SQL Injection, XSS, Path Traversal e Command Injection nos parâmetros das requisições |

Todo alerta recebe uma **severidade** (baixo/médio/alto/crítico), calculada como múltiplo do limite configurado.

## Formatos de log suportados

- `auto` — detecta o formato automaticamente (padrão)
- `auth` — `/var/log/auth.log` do Linux (sshd) e saída do `journalctl`
- `apache` — logs de acesso HTTP no formato "combined" (`access.log`)
- `nginx` — logs de acesso do Nginx (mesmo formato "combined" do Apache)
- `json` — logs estruturados em JSON, uma linha por evento (campos aceitos: `ip`/`ip_address`/`client_ip`, `status`/`status_code`, `path`/`url`/`request`)
- `geral` — qualquer log que contenha endereços IP

Arquivos `.gz` são lidos de forma transparente (ex.: `access.log.1.gz`), sem precisar descompactar antes.

## Instalação

Requer apenas **Python 3.8+** — sem dependências externas para rodar a ferramenta. Testado em Windows (PowerShell/cmd), macOS e distros Linux (Ubuntu, Debian, Fedora, Arch).

```bash
git clone https://github.com/x64gh0st/scarface.git
cd scarface
python scarface.py --demo
```

> No Linux/macOS, use `python3` em vez de `python` se o seu sistema não tiver o alias configurado.

No Linux, também tem um instalador automatizado — veja `install.sh` (checa o Python, testa a instalação e oferece registrar o comando `scarface` no PATH):
```bash
chmod +x install.sh
./install.sh
```

Alternativa via `pip` (empacotado com `pyproject.toml`, instala o comando `scarface` no PATH automaticamente):
```bash
pip install .
scarface --demo
```

Para rodar os testes unitários (opcional):
```bash
pip install pytest --break-system-packages
pytest test_scarface.py -v
```

## Como usar

```bash
# Analisar um log de autenticação SSH
python scarface.py auth.log

# Analisar um access.log, salvando relatório em Markdown e dados em JSON
python scarface.py access.log --saida relatorio.md --json dados.json

# Ajustar sensibilidade da detecção de brute force
python scarface.py auth.log --limite 3 --janela 60

# Ajustar a janela de tempo para considerar comprometimento de conta
python scarface.py auth.log --janela-comprometimento 300

# Rodar sem cores (útil ao redirecionar a saída para arquivo)
python scarface.py auth.log --sem-cor

# Testar com dados fictícios de SSH, sem precisar de um log real
python scarface.py --demo

# Testar com dados fictícios de HTTP (mostra escaneamento e ataques em URL)
python scarface.py --demo --demo-tipo apache

# Ignorar IPs confiáveis (rede interna, VPN) em todas as detecções
python scarface.py auth.log --whitelist 192.168.0.0/16,10.0.0.5

# Analisar um log de acesso rotacionado e comprimido, sem descompactar
python scarface.py access.log.1.gz --formato apache
```

### Opções disponíveis

| Opção | Descrição | Padrão |
|---|---|---|
| `arquivo` | Caminho do arquivo de log a analisar | — |
| `--demo` | Roda com um log fictício de demonstração | — |
| `--demo-tipo` | Qual log fictício usar com `--demo`: `auth` ou `apache` | `auth` |
| `--formato` | `auto`, `auth`, `apache` ou `geral` | `auto` |
| `--limite` | Nº de falhas para alertar brute force (inteiro > 0) | `5` |
| `--janela` | Janela de tempo em segundos para o brute force (inteiro ≥ 0; `0` desativa a janela) | `300` |
| `--limite-404` | Nº de 404 para alertar escaneamento (inteiro > 0) | `10` |
| `--janela-comprometimento` | Segundos entre a última falha e o sucesso para considerar comprometimento (inteiro > 0) | `600` |
| `--minimo-ips-distribuido` | Nº mínimo de IPs distintos visando o mesmo usuário para alertar brute force distribuído (inteiro > 0) | `3` |
| `--whitelist` | IPs/faixas CIDR a ignorar em todas as detecções, separados por vírgula | — |
| `--saida ARQUIVO.md` | Salva relatório em Markdown | — |
| `--json ARQUIVO.json` | Salva dados estruturados em JSON | — |
| `--sem-cor` | Desativa cores no terminal | — |
| `--versao` | Mostra a versão da ferramenta | — |

## Exemplo de saída

```
[ RESUMO ]
+ Brute force     : 2 IP(s)
+ Comprometimento : 1 IP(s)
+ Escaneamento    : 0 IP(s)
+ Ataques em URL  : 0 ocorrência(s)

[!] ALERTA - BRUTE FORCE
IP ....................: 203.0.113.7
Falhas totais .........: 38
Falhas na janela ......: 38 (300 s)
Alvo mais visado ......: root (19x)
Período ...............: 2026-09-17T09:12:00+00:00 ate 2026-09-17T09:12:59+00:00

[!] ALERTA - COMPROMETIMENTO EM ANDAMENTO
IP .....................: 198.51.100.22
Falhas imediatamente antes: 6
Login bem-sucedido .....: alice em 2026-09-17T10:07:45+00:00
Intervalo falha->sucesso: 144s
```

## Estrutura do projeto

```
scarface/
├── scarface.py               # ferramenta principal
├── test_scarface.py          # testes unitários (pytest)
├── install.sh                # instalador para Linux (checa Python, instala no PATH)
├── pyproject.toml            # empacotamento (pip install .)
├── .github/workflows/tests.yml  # CI: roda os testes em Ubuntu/Windows/macOS a cada push
├── .gitignore                # ignora relatórios/dados gerados pela própria ferramenta
├── CHANGELOG.md              # histórico de versões
└── README.md
```

## Como funciona por dentro

- **Parsing**: cada linha do log é transformada em um registro estruturado (`ip`, `data`, `usuário`, `evento`, `tipo`), com regex específicas por formato — inclusive regex separadas para `Failed/Accepted password` e `Invalid user`, já que têm estruturas de frase diferentes.
- **Brute force**: usa o algoritmo de janela deslizante com dois ponteiros (O(n)) para achar a maior rajada de falhas de um mesmo IP dentro do intervalo de tempo configurado.
- **Comprometimento**: exige uma sequência mínima de falhas *imediatamente* seguida de um sucesso dentro da janela configurada — evita falsos positivos de logins legítimos sem relação com tentativas antigas.
- **Escaneamento**: agrupa respostas 404 por IP e caminho acessado.
- **Ataques em URL**: aplica assinaturas regex conhecidas (SQLi, XSS, Path Traversal, Command Injection) sobre o caminho de cada requisição.

### Robustez

A ferramenta foi endurecida contra os casos mais comuns de falha em uso real:

- Validação de argumentos (ex.: `--limite 0` ou negativo é rejeitado com mensagem clara, em vez de gerar alertas inúteis)
- Arquivo vazio, inexistente, sem permissão de leitura, ou uma pasta passada por engano — cada caso tem uma mensagem específica
- Pasta de destino de `--saida`/`--json` é validada *antes* de processar o log inteiro
- Leitura tolerante a encoding (tenta UTF-8, cai para latin-1) — cobre logs gerados no Windows em `cp1252`
- `Ctrl+C` e pipes cortados (`scarface.py log | head`) encerram de forma limpa, sem traceback
- Qualquer erro inesperado é capturado no topo e mostrado de forma legível

### Compatibilidade entre sistemas operacionais

- **Cores no terminal**: no Windows, o script habilita automaticamente o processamento de códigos ANSI no console (necessário no `cmd.exe`/PowerShell legado); no Linux e macOS as cores já funcionam nativamente.
- **Caminhos de arquivo**: tratados com `pathlib`, então funcionam igual com `\` (Windows) ou `/` (Linux/macOS).
- Use `--sem-cor` em qualquer sistema se preferir saída sem formatação (por exemplo, ao redirecionar para um arquivo).

## Roadmap / possíveis melhorias

- [x] Suporte a Nginx e logs JSON estruturados
- [x] Whitelist de IPs confiáveis
- [x] Brute force distribuído (vários IPs, mesmo usuário)
- [x] Severidade por alerta (baixo/médio/alto/crítico)
- [x] Suporte a arquivos `.gz`
- [x] CI/CD (GitHub Actions) e empacotamento via `pyproject.toml`
- [ ] Suporte a Windows Event Log
- [ ] Exportação de IOCs (Indicators of Compromise) para integração com SIEMs
- [ ] Modo de monitoramento contínuo (tail -f em tempo real)
- [ ] Interface web simples para visualização dos relatórios
- [ ] Publicação no PyPI

## Autor

**Pedro Henrique Almeida** ([@devpedrohenrique.01](https://instagram.com/devpedrohenrique.01))
Estudante de Cibersegurança, com foco em Pentest / Red Team.

## Licença

Este projeto é distribuído para fins educacionais e de portfólio. Use por sua conta e risco — não utilize contra sistemas sem autorização explícita.
