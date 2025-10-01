#!/bin/bash

# =============================================================================
# SCRIPT PARA INICIAR TODOS OS SERVIÇOS
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
# INICIAR DOCKER SERVICES
# -----------------------------------------------------------------------------
start_docker_services() {
    print_info "Iniciando serviços Docker..."
    
    cd "$PROJECT_ROOT"
    
    if docker-compose up -d; then
        print_success "Serviços Docker iniciados"
    else
        print_error "Falha ao iniciar serviços Docker"
        exit 1
    fi
    
    # Aguardar serviços ficarem prontos
    print_info "Aguardando serviços ficarem prontos..."
    sleep 10
}

# -----------------------------------------------------------------------------
# INICIAR GATEWAY
# -----------------------------------------------------------------------------
start_gateway() {
    print_info "Iniciando Gateway Spring Cloud..."
    
    cd "$PROJECT_ROOT"
    
    # Verificar se já está rodando
    if curl -s --connect-timeout 5 "http://localhost:8083/actuator/health" > /dev/null; then
        print_warning "Gateway já está rodando"
        return 0
    fi
    
    # Iniciar gateway em background
    nohup ./gradlew bootRun > gateway.log 2>&1 &
    GATEWAY_PID=$!
    
    # Aguardar gateway ficar pronto
    print_info "Aguardando gateway ficar pronto..."
    for i in {1..30}; do
        if curl -s --connect-timeout 5 "http://localhost:8083/actuator/health" > /dev/null; then
            print_success "Gateway iniciado (PID: $GATEWAY_PID)"
            echo "$GATEWAY_PID" > gateway.pid
            return 0
        fi
        sleep 2
    done
    
    print_error "Gateway não ficou pronto em 60 segundos"
    exit 1
}

# -----------------------------------------------------------------------------
# VERIFICAR SERVIÇOS
# -----------------------------------------------------------------------------
check_services() {
    print_info "Verificando status dos serviços..."
    
    local services=(
        "http://localhost:8080/users:User Service"
        "http://localhost:8081/products:Product Service"
        "http://localhost:8082/orders:Order Service"
        "http://localhost:8084/realms/gateway-client:Keycloak"
        "http://localhost:8083/actuator/health:Gateway"
    )
    
    local all_ok=true
    
    for service in "${services[@]}"; do
        IFS=':' read -r url name <<< "$service"
        
        if curl -s --connect-timeout 5 "$url" > /dev/null; then
            print_success "$name está rodando"
        else
            print_error "$name não está rodando"
            all_ok=false
        fi
    done
    
    if [ "$all_ok" = true ]; then
        print_success "Todos os serviços estão rodando!"
    else
        print_warning "Alguns serviços não estão rodando"
    fi
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    INICIANDO TODOS OS SERVIÇOS"
    echo "============================================================================="
    echo
    
    start_docker_services
    echo
    
    start_gateway
    echo
    
    check_services
    echo
    
    echo "============================================================================="
    print_success "Todos os serviços foram iniciados!"
    echo
    print_info "URLs dos serviços:"
    echo "  Gateway: http://localhost:8083"
    echo "  User Service: http://localhost:8080"
    echo "  Product Service: http://localhost:8081"
    echo "  Order Service: http://localhost:8082"
    echo "  Keycloak: http://localhost:8084"
    echo
    print_info "Para parar todos os serviços:"
    echo "  ./scripts/deployment/stop-all.sh"
    echo "============================================================================="
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
