# 🔪 SCARFACE

**S**ystematic **C**yber **A**ttack **R**ecognition and **F**orensic **A**nalysis of **C**ritical **E**vents

Ferramenta de linha de comando em Python para análise forense de logs, feita para identificar rapidamente sinais de ataque em servidores Linux (SSH) e aplicações web (Apache/HTTP).

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
| 2 | **Comprometimento** | Um IP que falhou o login várias vezes seguidas e, logo depois, conseguiu acertar (indício de conta invadida) |
| 3 | **Escaneamento** | Rajada de respostas HTTP 404 do mesmo IP (alguém procurando diretórios, backups, painéis de admin) |
| 4 | **Ataques em URL** | Assinaturas de SQL Injection, XSS, Path Traversal e Command Injection nos parâmetros das requisições |

## Formatos de log suportados

- `auto` — detecta o formato automaticamente (padrão)
- `auth` — `/var/log/auth.log` do Linux (sshd)
- `apache` — logs de acesso HTTP (`access.log`)
- `geral` — qualquer log que contenha endereços IP

## Instalação

Requer apenas **Python 3.8+** — sem dependências externas para rodar a ferramenta.

```bash
git clone https://github.com/x64gh0st/scarface.git
cd scarface
python scarface.py --demo
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

# Rodar sem cores (útil ao redirecionar a saída para arquivo)
python scarface.py auth.log --sem-cor

# Testar com dados fictícios, sem precisar de um log real
python scarface.py --demo
```

### Opções disponíveis

| Opção | Descrição | Padrão |
|---|---|---|
| `arquivo` | Caminho do arquivo de log a analisar | — |
| `--demo` | Roda com um log fictício de demonstração | — |
| `--formato` | `auto`, `auth`, `apache` ou `geral` | `auto` |
| `--limite` | Nº de falhas para alertar brute force | `5` |
| `--janela` | Janela de tempo (segundos) para o brute force | `300` |
| `--limite-404` | Nº de 404 para alertar escaneamento | `10` |
| `--janela-comprometimento` | Segundos entre a última falha e o sucesso para considerar comprometimento | `600` |
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
├── scarface.py         # ferramenta principal
├── test_scarface.py    # testes unitários (pytest)
└── README.md
```

## Como funciona por dentro

- **Parsing**: cada linha do log é transformada em um registro estruturado (`ip`, `data`, `usuário`, `evento`, `tipo`), com regex específicas por formato.
- **Brute force**: usa o algoritmo de janela deslizante com dois ponteiros (O(n)) para achar a maior rajada de falhas de um mesmo IP dentro do intervalo de tempo configurado.
- **Comprometimento**: exige uma sequência mínima de falhas *imediatamente* seguida de um sucesso dentro da janela configurada — evita falsos positivos de logins legítimos sem relação com tentativas antigas.
- **Escaneamento**: agrupa respostas 404 por IP e caminho acessado.
- **Ataques em URL**: aplica assinaturas regex conhecidas (SQLi, XSS, Path Traversal, Command Injection) sobre o caminho de cada requisição.

## Roadmap / possíveis melhorias

- [ ] Suporte a mais formatos de log (Nginx, Windows Event Log)
- [ ] Exportação de IOCs (Indicators of Compromise) para integração com SIEMs
- [ ] Modo de monitoramento contínuo (tail -f em tempo real)
- [ ] Interface web simples para visualização dos relatórios

## Autor

**Pedro Henrique Almeida** ([@devpedrohenrique.01](https://instagram.com/devpedrohenrique.01))
Estudante de Cibersegurança, com foco em Pentest / Red Team.

## Licença

Este projeto é distribuído para fins educacionais e de portfólio. Use por sua conta e risco — não utilize contra sistemas sem autorização explícita.
