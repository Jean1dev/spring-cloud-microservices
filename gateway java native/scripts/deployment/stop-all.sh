#!/bin/bash

# =============================================================================
# SCRIPT PARA PARAR TODOS OS SERVIÇOS
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
# PARAR GATEWAY
# -----------------------------------------------------------------------------
stop_gateway() {
    print_info "Parando Gateway Spring Cloud..."
    
    cd "$PROJECT_ROOT"
    
    if [ -f "gateway.pid" ]; then
        GATEWAY_PID=$(cat gateway.pid)
        
        if kill -0 "$GATEWAY_PID" 2>/dev/null; then
            kill "$GATEWAY_PID"
            print_success "Gateway parado (PID: $GATEWAY_PID)"
        else
            print_warning "Gateway não estava rodando"
        fi
        
        rm -f gateway.pid
    else
        print_warning "Arquivo PID do gateway não encontrado"
        
        # Tentar parar por processo
        GATEWAY_PID=$(pgrep -f "spring-boot:run")
        if [ -n "$GATEWAY_PID" ]; then
            kill "$GATEWAY_PID"
            print_success "Gateway parado (PID: $GATEWAY_PID)"
        else
            print_info "Gateway não estava rodando"
        fi
    fi
}

# -----------------------------------------------------------------------------
# PARAR DOCKER SERVICES
# -----------------------------------------------------------------------------
stop_docker_services() {
    print_info "Parando serviços Docker..."
    
    cd "$PROJECT_ROOT"
    
    if docker-compose down; then
        print_success "Serviços Docker parados"
    else
        print_error "Falha ao parar serviços Docker"
    fi
}

# -----------------------------------------------------------------------------
# VERIFICAR SERVIÇOS PARADOS
# -----------------------------------------------------------------------------
check_services_stopped() {
    print_info "Verificando se todos os serviços foram parados..."
    
    local services=(
        "http://localhost:8080:User Service"
        "http://localhost:8081:Product Service"
        "http://localhost:8082:Order Service"
        "http://localhost:8083:Gateway"
        "http://localhost:8084:Keycloak"
    )
    
    local all_stopped=true
    
    for service in "${services[@]}"; do
        IFS=':' read -r url name <<< "$service"
        
        if curl -s --connect-timeout 2 "$url" > /dev/null; then
            print_warning "$name ainda está rodando"
            all_stopped=false
        else
            print_success "$name foi parado"
        fi
    done
    
    if [ "$all_stopped" = true ]; then
        print_success "Todos os serviços foram parados!"
    else
        print_warning "Alguns serviços ainda estão rodando"
    fi
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    PARANDO TODOS OS SERVIÇOS"
    echo "============================================================================="
    echo
    
    stop_gateway
    echo
    
    stop_docker_services
    echo
    
    check_services_stopped
    echo
    
    echo "============================================================================="
    print_success "Todos os serviços foram parados!"
    echo "============================================================================="
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
