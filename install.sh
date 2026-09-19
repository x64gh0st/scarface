#!/usr/bin/env bash
# ============================================================
# install.sh - instalador do SCARFACE para Linux
#
# O que este script faz:
#   1. Confere se o Python 3.8+ está instalado (avisa como instalar
#      se não estiver, de acordo com a distro detectada)
#   2. Dá permissão de execução ao scarface.py
#   3. Roda um teste rápido (--demo) pra confirmar que está funcional
#   4. Opcionalmente instala o comando `scarface` no PATH, para
#      poder rodar de qualquer pasta sem precisar digitar o
#      caminho completo nem "python3 scarface.py"
#      (usa /usr/local/bin com sudo, ou ~/.local/bin sem sudo)
#   5. Opcionalmente instala o pytest para rodar os testes
#
# Uso:
#   chmod +x install.sh
#   ./install.sh              # instala
#   ./install.sh --uninstall  # remove o comando global 'scarface'
# ============================================================

set -euo pipefail

VERDE='\033[0;32m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
SEM_COR='\033[0m'

info()  { echo -e "${VERDE}[*]${SEM_COR} $1"; }
aviso() { echo -e "${AMARELO}[!]${SEM_COR} $1"; }
erro()  { echo -e "${VERMELHO}[erro]${SEM_COR} $1"; }

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR_SCRIPT"

DESTINO_SUDO="/usr/local/bin/scarface"
DESTINO_LOCAL="$HOME/.local/bin/scarface"

# ------------------------------------------------------------
# Modo desinstalação
# ------------------------------------------------------------
if [[ "${1:-}" == "--uninstall" ]]; then
    echo "=================================================="
    echo "  Desinstalador do SCARFACE"
    echo "=================================================="
    echo
    removido=0
    if [ -f "$DESTINO_SUDO" ]; then
        if sudo rm -f "$DESTINO_SUDO"; then
            info "Removido: $DESTINO_SUDO"
            removido=1
        fi
    fi
    if [ -f "$DESTINO_LOCAL" ]; then
        rm -f "$DESTINO_LOCAL"
        info "Removido: $DESTINO_LOCAL"
        removido=1
    fi
    if [ "$removido" -eq 0 ]; then
        aviso "Nenhuma instalação global do SCARFACE foi encontrada."
    else
        info "Desinstalação concluída."
    fi
    exit 0
fi

echo "=================================================="
echo "  Instalador do SCARFACE"
echo "=================================================="
echo

# ------------------------------------------------------------
# 1. Verifica se o arquivo principal existe nesta pasta
# ------------------------------------------------------------
if [ ! -f "scarface.py" ]; then
    erro "scarface.py não encontrado em '$DIR_SCRIPT'."
    erro "Rode este install.sh de dentro da pasta do projeto."
    exit 1
fi

# ------------------------------------------------------------
# 2. Verifica o Python 3.8+
# ------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    VERSAO_PYTHON="$(python3 --version 2>&1)"
    info "Python encontrado: $VERSAO_PYTHON"
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
        erro "O SCARFACE precisa do Python 3.8 ou mais recente. Atualize seu Python e rode este instalador de novo."
        exit 1
    fi
else
    erro "Python 3 não encontrado."
    if command -v apt >/dev/null 2>&1; then
        aviso "Instale com: sudo apt update && sudo apt install python3 -y"
    elif command -v dnf >/dev/null 2>&1; then
        aviso "Instale com: sudo dnf install python3 -y"
    elif command -v pacman >/dev/null 2>&1; then
        aviso "Instale com: sudo pacman -S python --noconfirm"
    else
        aviso "Instale o Python 3 usando o gerenciador de pacotes da sua distro."
    fi
    exit 1
fi

# ------------------------------------------------------------
# 3. Permissão de execução
# ------------------------------------------------------------
chmod +x scarface.py
info "Permissão de execução concedida a scarface.py"

# ------------------------------------------------------------
# 4. Teste rápido (modo demo) para confirmar que está funcional
# ------------------------------------------------------------
info "Rodando teste rápido (--demo --sem-cor)..."
if python3 scarface.py --demo --sem-cor >/dev/null 2>&1; then
    info "Teste OK — o SCARFACE está funcional."
else
    erro "O teste com --demo falhou. Rode 'python3 scarface.py --demo' manualmente para ver o erro completo."
    exit 1
fi

# ------------------------------------------------------------
# 5. Oferece instalar no PATH (comando global 'scarface')
# ------------------------------------------------------------
echo
read -r -p "Deseja instalar o comando 'scarface' globalmente? [s/N] " resposta
if [[ "$resposta" =~ ^[sS]$ ]]; then
    if command -v sudo >/dev/null 2>&1; then
        read -r -p "  Usar sudo para instalar em $DESTINO_SUDO (acessível a todos os usuários)? [S/n] " usar_sudo
    else
        usar_sudo="n"
    fi

    if [[ ! "$usar_sudo" =~ ^[nN]$ ]] && command -v sudo >/dev/null 2>&1; then
        if sudo cp scarface.py "$DESTINO_SUDO" && sudo chmod +x "$DESTINO_SUDO"; then
            info "Instalado em $DESTINO_SUDO — rode 'scarface --demo' de qualquer pasta."
        else
            erro "Não consegui copiar para $DESTINO_SUDO."
        fi
    else
        mkdir -p "$HOME/.local/bin"
        cp scarface.py "$DESTINO_LOCAL"
        chmod +x "$DESTINO_LOCAL"
        info "Instalado em $DESTINO_LOCAL"
        if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
            aviso "~/.local/bin não está no seu PATH ainda. Adicione ao seu ~/.bashrc ou ~/.zshrc:"
            aviso "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        else
            info "Rode 'scarface --demo' de qualquer pasta."
        fi
    fi
else
    info "Ok, sem instalação global. Use './scarface.py' ou 'python3 scarface.py' dentro desta pasta."
fi

# ------------------------------------------------------------
# 6. Oferece instalar o pytest para os testes unitários
# ------------------------------------------------------------
echo
if [ -f "test_scarface.py" ]; then
    read -r -p "Deseja instalar o pytest para rodar os testes unitários? [s/N] " resposta_testes
    if [[ "$resposta_testes" =~ ^[sS]$ ]]; then
        if command -v pip3 >/dev/null 2>&1; then
            if pip3 install pytest --break-system-packages 2>/dev/null || pip3 install pytest; then
                info "pytest instalado. Rode: pytest test_scarface.py -v"
            else
                aviso "Não consegui instalar o pytest automaticamente. Tente manualmente:"
                aviso "  pip3 install pytest --break-system-packages"
            fi
        else
            aviso "pip3 não encontrado. Instale-o primeiro (ex.: sudo apt install python3-pip)."
        fi
    fi
fi

echo
info "Instalação concluída — $(python3 scarface.py --versao)"
echo "  Exemplos de uso:"
echo "    python3 scarface.py --demo"
echo "    python3 scarface.py --demo --demo-tipo apache"
echo "    python3 scarface.py auth.log --saida relatorio.md --json dados.json"
echo "    sudo python3 scarface.py /var/log/auth.log"
echo
echo "  Para desinstalar o comando global: ./install.sh --uninstall"
