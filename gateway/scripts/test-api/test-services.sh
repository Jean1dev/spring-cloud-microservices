#!/bin/bash

# =============================================================================
# SCRIPT PARA TESTAR OS SERVIÇOS INDIVIDUAIS
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
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
# TESTAR SERVIÇO
# -----------------------------------------------------------------------------
test_service() {
    local service_name="$1"
    local service_url="$2"
    local endpoint="$3"
    
    print_info "Testando $service_name..."
    
    if curl -s --connect-timeout 5 "$service_url$endpoint" > /dev/null; then
        print_success "$service_name está rodando em $service_url"
        
        # Testar endpoint específico
        RESPONSE=$(curl -s -w "\n%{http_code}" "$service_url$endpoint")
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        
        if [ "$HTTP_CODE" = "200" ]; then
            print_success "$service_name endpoint OK (HTTP $HTTP_CODE)"
        else
            print_warning "$service_name endpoint retornou HTTP $HTTP_CODE"
        fi
        echo "Resposta: $BODY"
    else
        print_error "$service_name não está rodando em $service_url"
        print_info "Execute: docker-compose up $service_name"
    fi
    echo
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    TESTE DOS SERVIÇOS INDIVIDUAIS"
    echo "============================================================================="
    echo
    
    test_service "User Service" "$USER_SERVICE_URL" "/users"
    test_service "Product Service" "$PRODUCT_SERVICE_URL" "/products"
    test_service "Order Service" "$ORDER_SERVICE_URL" "/orders"
    
    echo "============================================================================="
    print_success "Testes dos serviços concluídos!"
    echo "============================================================================="
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
