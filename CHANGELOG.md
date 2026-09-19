# Changelog

Todas as mudanças notáveis do projeto SCARFACE são documentadas aqui.

## [2.0.0-alpha] - 2026-09-19

Primeira versão considerada **alpha funcional** — sai do estágio de protótipo/demo e passa a ser usável em cenários reais, com correções de bugs e robustez contra erros comuns.

### Adicionado
- `--demo-tipo {auth,apache}`: agora dá pra testar o modo de demonstração também com log HTTP (escaneamento e ataques de URL), não só SSH.
- `--janela-comprometimento`: controla a janela de tempo (segundos) usada na detecção de comprometimento de conta.
- Validação de argumentos numéricos (`--limite`, `--janela`, `--limite-404`, `--janela-comprometimento`) com mensagens de erro claras em vez de comportamento silencioso incorreto.
- Suporte a cores ANSI no Windows (`cmd.exe`/PowerShell legado), habilitado automaticamente via `ctypes`.
- Leitura de log tolerante a encoding (UTF-8 com fallback para latin-1).
- Tratamento de erros para arquivo vazio, pasta em vez de arquivo, sem permissão de leitura/escrita, `Ctrl+C` e pipe cortado.
- `install.sh`: instalador para Linux com checagem de Python 3.8+, teste automático pós-instalação, instalação global do comando `scarface` (com ou sem sudo) e opção `--uninstall`.
- `test_scarface.py`: suíte de testes unitários (pytest) cobrindo os bugs corrigidos abaixo.
- `.gitignore` cobrindo arquivos de saída (`dados*.json`, `relatorio*.md`, `demo_*.log`) e artefatos comuns de SO/editor.

### Corrigido
- **Regex de autenticação SSH**: `Failed password`/`Accepted` e `Invalid user` tinham estruturas de frase diferentes e eram capturados por um único regex genérico, causando usuário/IP trocados ou vazios em alguns logs. Agora são dois regex específicos.
- **Falso positivo na detecção de comprometimento**: antes, qualquer login bem-sucedido posterior a *qualquer* falha antiga (mesmo dias de distância, sem relação nenhuma) disparava o alerta. Agora exige uma sequência mínima de falhas *imediatamente* seguida de um sucesso dentro de uma janela de tempo configurável.
- `demo_apache()` existia no código mas nunca era chamada — o modo `--demo` só testava o formato SSH.

### Alterado
- Saída no console simplificada: mostra apenas o banner e a versão; o relatório completo (brute force, comprometimento, escaneamento, ataques) continua disponível via `--saida` (Markdown) e `--json`.

## [1.0.0] - versão inicial

- Detecção de brute force (janela deslizante O(n)), comprometimento, escaneamento (rajada de 404) e ataques em URL (SQLi, XSS, Path Traversal, Command Injection).
- Suporte a formatos `auth`, `apache` e `geral`, com detecção automática.
- Saída colorida no terminal, relatório em Markdown e dados em JSON.
- Modo `--demo` com log fictício de SSH.
