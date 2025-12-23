#!/bin/bash

# =============================================================================
# SCRIPT PARA TESTAR CIRCUIT BREAKER
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
GATEWAY_URL="http://localhost:8083"
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
# OBTER TOKEN
# -----------------------------------------------------------------------------
get_token() {
    print_info "Obtendo token do Keycloak..."
    
    TOKEN_SCRIPT="$PROJECT_ROOT/scripts/auth/quick-token.sh"
    
    if [ ! -f "$TOKEN_SCRIPT" ]; then
        print_error "Script de token não encontrado: $TOKEN_SCRIPT"
        exit 1
    fi
    
    TOKEN_OUTPUT=$("$TOKEN_SCRIPT" 2>/dev/null)
    ACCESS_TOKEN=$(echo "$TOKEN_OUTPUT" | grep "Bearer" | cut -d' ' -f2)
    
    if [ -z "$ACCESS_TOKEN" ]; then
        print_error "Falha ao obter token"
        echo "$TOKEN_OUTPUT"
        exit 1
    fi
    
    print_success "Token obtido com sucesso"
}

# -----------------------------------------------------------------------------
# TESTAR CIRCUIT BREAKER
# -----------------------------------------------------------------------------
test_circuit_breaker() {
    local service_name="$1"
    local endpoint="$2"
    local requests="$3"
    
    print_info "Testando Circuit Breaker para $service_name ($requests requisições)..."
    
    local success_count=0
    local failure_count=0
    local fallback_count=0
    
    for i in $(seq 1 $requests); do
        RESPONSE=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$GATEWAY_URL$endpoint")
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        BODY=$(echo "$RESPONSE" | head -n -1)
        
        case $HTTP_CODE in
            200)
                success_count=$((success_count + 1))
                ;;
            503)
                fallback_count=$((fallback_count + 1))
                ;;
            *)
                failure_count=$((failure_count + 1))
                ;;
        esac
        
        echo -n "."
        sleep 0.1
    done
    
    echo
    print_info "Resultados para $service_name:"
    echo "  Sucessos: $success_count"
    echo "  Falhas: $failure_count"
    echo "  Fallbacks: $fallback_count"
    echo
}

# -----------------------------------------------------------------------------
# VERIFICAR STATUS DO CIRCUIT BREAKER
# -----------------------------------------------------------------------------
check_circuit_breaker_status() {
    print_info "Verificando status dos Circuit Breakers..."
    
    RESPONSE=$(curl -s "$GATEWAY_URL/actuator/circuitbreakers")
    
    if [ $? -eq 0 ]; then
        print_success "Status dos Circuit Breakers:"
        echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    else
        print_warning "Não foi possível obter status dos Circuit Breakers"
    fi
    echo
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    TESTE DE CIRCUIT BREAKER"
    echo "============================================================================="
    echo
    
    # Verificar se o gateway está rodando
    print_info "Verificando se o gateway está rodando..."
    if ! curl -s --connect-timeout 5 "$GATEWAY_URL/actuator/health" > /dev/null; then
        print_error "Gateway não está rodando em $GATEWAY_URL"
        print_info "Execute: ./gradlew bootRun"
        exit 1
    fi
    print_success "Gateway está rodando"
    echo
    
    # Obter token
    get_token
    echo
    
    # Verificar status inicial
    check_circuit_breaker_status
    
    # Testar circuit breakers
    print_info "Iniciando testes de Circuit Breaker..."
    echo "Nota: Para ativar o circuit breaker, pare um dos serviços e execute este script"
    echo
    
    test_circuit_breaker "User Service" "/users" 10
    test_circuit_breaker "Product Service" "/products" 10
    test_circuit_breaker "Order Service" "/orders" 10
    
    # Verificar status final
    check_circuit_breaker_status
    
    echo "============================================================================="
    print_success "Testes de Circuit Breaker concluídos!"
    echo "============================================================================="
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
