#!/bin/bash

# =============================================================================
# SCRIPT PARA LIMPAR LOGS
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
BUILD_DIR="$PROJECT_ROOT/build"

# -----------------------------------------------------------------------------
# CORES
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# -----------------------------------------------------------------------------
# LIMPAR LOGS
# -----------------------------------------------------------------------------
clean_logs() {
    print_info "Limpando logs da aplicação..."
    
    if [ -d "$LOG_DIR" ]; then
        rm -rf "$LOG_DIR"/*
        print_success "Logs da aplicação limpos"
    else
        print_info "Diretório de logs não existe: $LOG_DIR"
    fi
}

# -----------------------------------------------------------------------------
# LIMPAR BUILD
# -----------------------------------------------------------------------------
clean_build() {
    print_info "Limpando diretório de build..."
    
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"/*
        print_success "Diretório de build limpo"
    else
        print_info "Diretório de build não existe: $BUILD_DIR"
    fi
}

# -----------------------------------------------------------------------------
# LIMPAR DOCKER
# -----------------------------------------------------------------------------
clean_docker() {
    print_info "Limpando containers e volumes Docker..."
    
    # Parar containers
    docker-compose down 2>/dev/null || true
    
    # Remover containers órfãos
    docker container prune -f 2>/dev/null || true
    
    # Remover volumes não utilizados
    docker volume prune -f 2>/dev/null || true
    
    # Remover imagens não utilizadas
    docker image prune -f 2>/dev/null || true
    
    print_success "Docker limpo"
}

# -----------------------------------------------------------------------------
# LIMPAR TUDO
# -----------------------------------------------------------------------------
clean_all() {
    print_info "Limpando tudo..."
    
    clean_logs
    clean_build
    clean_docker
    
    print_success "Limpeza completa realizada!"
}

# -----------------------------------------------------------------------------
# AJUDA
# -----------------------------------------------------------------------------
show_help() {
    echo "Uso: $0 [OPÇÃO]"
    echo
    echo "Opções:"
    echo "  logs     Limpa apenas os logs da aplicação"
    echo "  build    Limpa apenas o diretório de build"
    echo "  docker   Limpa containers e volumes Docker"
    echo "  all      Limpa tudo (logs, build e docker)"
    echo "  -h       Exibe esta ajuda"
    echo
    echo "Exemplos:"
    echo "  $0 logs     # Limpa apenas logs"
    echo "  $0 all      # Limpa tudo"
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    case "${1:-all}" in
        logs)
            clean_logs
            ;;
        build)
            clean_build
            ;;
        docker)
            clean_docker
            ;;
        all)
            clean_all
            ;;
        -h|--help)
            show_help
            ;;
        *)
            print_error "Opção inválida: $1"
            show_help
            exit 1
            ;;
    esac
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
