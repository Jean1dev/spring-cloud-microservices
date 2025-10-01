#!/bin/bash

# =============================================================================
# SCRIPT PARA TESTAR O GATEWAY COM TOKEN KEYCLOAK
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
    
    # Usar o script de autenticação
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
# TESTAR ENDPOINT
# -----------------------------------------------------------------------------
test_endpoint() {
    local endpoint="$1"
    local description="$2"
    
    print_info "Testando $description..."
    
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        "$GATEWAY_URL$endpoint")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        print_success "$description - OK (HTTP $HTTP_CODE)"
        echo "Resposta: $BODY"
    else
        print_error "$description - FALHOU (HTTP $HTTP_CODE)"
        echo "Resposta: $BODY"
    fi
    echo
}

# -----------------------------------------------------------------------------
# TESTAR SEM TOKEN (DEVE FALHAR)
# -----------------------------------------------------------------------------
test_without_token() {
    local endpoint="$1"
    local description="$2"
    
    print_info "Testando $description (sem token - deve falhar)..."
    
    RESPONSE=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL$endpoint")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        print_success "$description - CORRETO (HTTP $HTTP_CODE - acesso negado)"
    else
        print_warning "$description - INESPERADO (HTTP $HTTP_CODE)"
    fi
    echo "Resposta: $BODY"
    echo
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    TESTE DO GATEWAY COM KEYCLOAK"
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
    
    # Testar endpoints protegidos
    print_info "Testando endpoints protegidos..."
    test_endpoint "/users" "User Service"
    test_endpoint "/products" "Product Service"
    test_endpoint "/orders" "Order Service"
    
    # Testar endpoints sem token
    print_info "Testando endpoints sem token (deve falhar)..."
    test_without_token "/users" "User Service"
    test_without_token "/products" "Product Service"
    test_without_token "/orders" "Order Service"
    
    # Testar endpoints públicos
    print_info "Testando endpoints públicos..."
    test_endpoint "/actuator/health" "Health Check"
    
    echo "============================================================================="
    print_success "Testes concluídos!"
    echo "============================================================================="
}

# Executar se chamado diretamente
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
