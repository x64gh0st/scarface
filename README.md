# SCARFACE

Scanner de portas TCP em Python, inspirado no nmap. Um arquivo só, sem dependências, sem precisar de root. Funciona em Linux, macOS e Windows.

```
  ___  ___   _   ___ ___ _   ___ ___
 / __|/ __| /_\ | _ \ __/_\ / __| __|
 \__ \ (__ / _ \|   / _/ _ \ (__| _|
 |___/\___/_/ \_\_|_\_/_/ \_\___|___|
```

> **Uso responsável:** escaneie apenas sistemas seus ou com autorização explícita. Escanear redes de terceiros sem permissão pode ser crime.

## O que ele faz

- **Descoberta de host** sem root: sonda portas comuns por TCP (`-Pn` pula esta etapa).
- **Escaneamento de portas** concorrente, com estados `aberta`, `fechada` e `filtrada`.
- **Identificação de serviço** pela porta e **detecção de versão** por banner (`-sV`), inclusive servidores web em portas não padrão e TLS em 443/8443.
- **Alvos flexíveis:** IP, nome de host, faixa CIDR (até 4096 hosts) e vários alvos de uma vez.
- **Saída em JSON** para integrar com outras ferramentas.

## Instalação

Requer **Python 3.8+**.

```bash
# recomendado: isola o programa e coloca o comando `scarface` no PATH
pipx install scarface-scanner

# ou com pip
pip install scarface-scanner
```

Direto do código-fonte:

```bash
git clone https://github.com/x64gh0st/scarface.git
cd scarface
pip install .          # ou apenas: python scarface.py --versao
```

No Linux também há o `install.sh`, que checa o Python, testa a instalação e oferece registrar o comando no PATH.

## Uso

```bash
scarface 192.168.0.1                          # portas 1-1024
scarface scanme.nmap.org -p 22,80,443 -sV     # portas específicas + versão dos serviços
scarface 192.168.0.0/24 -F                    # rede inteira, portas mais comuns
scarface 10.0.0.5 -p- -t 500 -o resultado.json  # todas as portas, salvando em JSON
scarface 10.0.0.5 -Pn                         # host que bloqueia as sondagens de descoberta
```

Exemplo de saída:

```
Relatório de scan para 127.0.0.1
Host ativo (0.0010s de latência).
Não mostradas: 1022 fechada(s), 0 filtrada(s).
PORTA     ESTADO    SERVIÇO         VERSÃO/BANNER
22/tcp    aberta    ssh             SSH-2.0-OpenSSH_9.6p1 Ubuntu
8080/tcp  aberta    http-proxy      nginx/1.25.3
```

### Opções

| Opção | Descrição | Padrão |
|---|---|---|
| `alvo` | IP, nome de host ou CIDR (um ou mais) | — |
| `-p`, `--portas` | `80`, `22,80,443`, `1-1000` ou `-` para todas | `1-1024` |
| `-F`, `--rapido` | Só as portas mais comuns | — |
| `-sV`, `--banner` | Identifica versão/banner dos serviços abertos | — |
| `-Pn`, `--sem-ping` | Não checa se o host está ativo | — |
| `-t`, `--threads` | Conexões simultâneas (máx. 1000) | `100` |
| `-T`, `--timeout` | Tempo máximo por porta, em segundos | `1.0` |
| `-o`, `--saida` | Salva o resultado em JSON | — |
| `--sem-cor` | Desativa as cores | — |
| `--versao` | Mostra a versão | — |

### Estados das portas

- **aberta:** a conexão foi aceita.
- **fechada:** o host recusou a conexão; tem alguém lá, mas nada escutando.
- **filtrada:** sem resposta, normalmente por causa de firewall.

## Limitações

O SCARFACE faz *connect scan* (conexão TCP completa). Comparado ao nmap, **não** tem SYN scan, UDP, detecção de sistema operacional, scripts nem IPv6. Por fazer a conexão completa, os scans aparecem nos logs do alvo.

No Windows, uma porta fechada pode demorar cerca de 2 segundos para recusar a conexão. Com o timeout padrão de 1s ela pode aparecer como `filtrada`; use `-T 3` se precisar distinguir os dois casos.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest -v
python -m build && twine check dist/*
```

Os testes sobem serviços reais em `127.0.0.1`, então não precisam de rede externa.

## Autor

**Pedro Henrique Almeida** ([@devpedrohenrique.01](https://instagram.com/devpedrohenrique.01)), estudante de Cibersegurança com foco em Pentest / Red Team.

## Licença

[MIT](LICENSE). Use por sua conta e risco, e apenas com autorização sobre os alvos.
