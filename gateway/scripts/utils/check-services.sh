#!/bin/bash

# =============================================================================
# SCRIPT PARA VERIFICAR STATUS DOS SERVIÇOS
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
GATEWAY_URL="http://localhost:8083"
KEYCLOAK_URL="http://localhost:8084"
USER_SERVICE_URL="http://localhost:8080"
PRODUCT_SERVICE_URL="http://localhost:8081"
ORDER_SERVICE_URL="http://localhost:8082"

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
# VERIFICAR SERVIÇO
# -----------------------------------------------------------------------------
check_service() {
    local service_name="$1"
    local service_url="$2"
    local health_endpoint="$3"
    
    print_info "Verificando $service_name..."
    
    if curl -s --connect-timeout 5 "$service_url$health_endpoint" > /dev/null; then
        print_success "$service_name está rodando em $service_url"
        return 0
    else
        print_error "$service_name não está rodando em $service_url"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# VERIFICAR DOCKER CONTAINERS
# -----------------------------------------------------------------------------
check_docker_containers() {
    print_info "Verificando containers Docker..."
    
    local containers=("user-service" "product-service" "order-service" "keycloak")
    local running_count=0
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "$container"; then
            print_success "Container $container está rodando"
            running_count=$((running_count + 1))
        else
            print_error "Container $container não está rodando"
        fi
    done
    
    echo
    print_info "Containers rodando: $running_count/${#containers[@]}"
    echo
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    VERIFICAÇÃO DE STATUS DOS SERVIÇOS"
    echo "============================================================================="
    echo
    
    local all_services_ok=true
    
    # Verificar containers Docker
    check_docker_containers
    
    # Verificar serviços
    check_service "Gateway" "$GATEWAY_URL" "/actuator/health" || all_services_ok=false
    check_service "Keycloak" "$KEYCLOAK_URL" "/realms/gateway-client" || all_services_ok=false
    check_service "User Service" "$USER_SERVICE_URL" "/users" || all_services_ok=false
    check_service "Product Service" "$PRODUCT_SERVICE_URL" "/products" || all_services_ok=false
    check_service "Order Service" "$ORDER_SERVICE_URL" "/orders" || all_services_ok=false
    
    echo "============================================================================="
    
    if [ "$all_services_ok" = true ]; then
        print_success "Todos os serviços estão rodando!"
    else
        print_warning "Alguns serviços não estão rodando."
        echo
        print_info "Para iniciar todos os serviços:"
        echo "  docker-compose up -d"
        echo
        print_info "Para iniciar apenas o gateway:"
        echo "  ./gradlew bootRun"
    fi
    
    echo "============================================================================="
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
