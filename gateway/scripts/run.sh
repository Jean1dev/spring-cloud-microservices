#!/bin/bash

# =============================================================================
# SCRIPT PRINCIPAL PARA EXECUTAR OUTROS SCRIPTS
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------------
# CORES
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_header() { echo -e "${CYAN}$1${NC}"; }

# -----------------------------------------------------------------------------
# AJUDA
# -----------------------------------------------------------------------------
show_help() {
    echo "============================================================================="
    print_header "                    SCRIPT PRINCIPAL - GATEWAY SPRING CLOUD"
    echo "============================================================================="
    echo
    echo "Uso: $0 [CATEGORIA] [SCRIPT]"
    echo
    print_header "CATEGORIAS DISPONÍVEIS:"
    echo
    echo "  auth       Scripts de autenticação e tokens"
    echo "  test-api   Scripts de teste de APIs"
    echo "  utils      Scripts de utilidade"
    echo "  deploy     Scripts de deployment"
    echo
    print_header "SCRIPTS DISPONÍVEIS:"
    echo
    echo "  AUTHENTICATION:"
    echo "    $0 auth token          # Obter token do Keycloak (completo)"
    echo "    $0 auth quick-token    # Obter token rapidamente"
    echo
    echo "  TEST API:"
    echo "    $0 test-api gateway    # Testar gateway com token"
    echo "    $0 test-api services   # Testar serviços individuais"
    echo "    $0 test-api circuit    # Testar circuit breaker"
    echo "    $0 test-api demo       # Demonstração completa"
    echo "    $0 test-api simple     # Teste simples (sem jq)"
    echo "    $0 test-api performance # Testes de performance"
    echo
    echo "  UTILS:"
    echo "    $0 utils check         # Verificar status dos serviços"
    echo "    $0 utils clean         # Limpar logs e build"
    echo
    echo "  DEPLOYMENT:"
    echo "    $0 deploy start        # Iniciar todos os serviços"
    echo "    $0 deploy stop         # Parar todos os serviços"
    echo
    echo "  EXEMPLOS:"
    echo "    $0 auth token          # Obter token completo"
    echo "    $0 test-api gateway    # Testar gateway"
    echo "    $0 utils check         # Verificar serviços"
    echo
    echo "============================================================================="
}

# -----------------------------------------------------------------------------
# EXECUTAR SCRIPT
# -----------------------------------------------------------------------------
run_script() {
    local category="$1"
    local script="$2"
    local script_path="$SCRIPT_DIR/$category/$script.sh"
    
    if [ ! -f "$script_path" ]; then
        print_error "Script não encontrado: $script_path"
        echo
        show_help
        exit 1
    fi
    
    if [ ! -x "$script_path" ]; then
        print_warning "Script não é executável, corrigindo permissões..."
        chmod +x "$script_path"
    fi
    
    print_info "Executando: $script_path"
    echo
    exec "$script_path" "${@:3}"
}

# -----------------------------------------------------------------------------
# LISTAR SCRIPTS
# -----------------------------------------------------------------------------
list_scripts() {
    local category="$1"
    
    if [ -z "$category" ]; then
        print_header "CATEGORIAS DISPONÍVEIS:"
        for dir in "$SCRIPT_DIR"/*; do
            if [ -d "$dir" ]; then
                echo "  $(basename "$dir")"
            fi
        done
        return
    fi
    
    local category_dir="$SCRIPT_DIR/$category"
    
    if [ ! -d "$category_dir" ]; then
        print_error "Categoria não encontrada: $category"
        exit 1
    fi
    
    print_header "SCRIPTS DISPONÍVEIS EM $category:"
    for script in "$category_dir"/*.sh; do
        if [ -f "$script" ]; then
            echo "  $(basename "$script" .sh)"
        fi
    done
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    case "${1:-help}" in
        help|--help|-h)
            show_help
            ;;
        list|ls)
            list_scripts "$2"
            ;;
        auth)
            run_script "auth" "${2:-token}" "${@:3}"
            ;;
        test-api)
            run_script "test-api" "${2:-gateway}" "${@:3}"
            ;;
        utils)
            run_script "utils" "${2:-check}" "${@:3}"
            ;;
        deploy)
            run_script "deployment" "${2:-start}" "${@:3}"
            ;;
        *)
            print_error "Categoria inválida: $1"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
