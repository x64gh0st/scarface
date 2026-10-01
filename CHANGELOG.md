# Changelog

Todas as mudanças notáveis do SCARFACE são documentadas aqui.

## [3.0.0] - 2026-09-29

Reescrita completa: o SCARFACE deixa de ser um analisador de logs e passa a ser um **scanner de portas TCP** inspirado no nmap. Primeira versão estável.

### Adicionado
- Descoberta de hosts sem root (sondagem TCP em portas comuns; uma recusa de conexão também prova que o host está ativo). `-Pn` pula essa etapa.
- Escaneamento TCP concorrente (`-t`) com timeout configurável (`-T`).
- Alvos: IP, nome de host, faixa CIDR (até 4096 hosts) e múltiplos alvos na mesma linha.
- Seleção de portas: lista, faixas, todas (`-p-`) ou as mais comuns (`-F`).
- Estados de porta `aberta`, `fechada` e `filtrada`.
- Identificação do serviço pela porta e detecção de versão por banner (`-sV`), incluindo servidores web em portas não padrão e TLS em 443/8443.
- Saída em JSON (`-o`) e opção `--sem-cor`.
- Suíte de testes com serviços locais reais (pytest).
- Empacotamento na PyPI como `scarface-scanner` (comando `scarface`), CI em Ubuntu/Windows/macOS, `LICENSE` MIT e `install.sh` atualizado.

### Removido
- Análise de logs (brute force, comprometimento, ataques em URL) e o modo `--demo`. A última versão com essas funções é a 2.1.0-alpha, disponível na tag v2.1.0-alpha.

## [2.0.0-alpha] - 2026-09-19

### Adicionado
- Modo de demonstração com log HTTP, validação de argumentos, cores ANSI no Windows, leitura tolerante a encoding, `install.sh` e testes unitários.

### Corrigido
- Regex de autenticação SSH e falso positivo na detecção de comprometimento.

## [1.0.0] - versão inicial

- Analisador de logs com detecção de brute force, comprometimento, escaneamento e ataques em URL.
