#!/bin/bash

# Cores para formatação
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configurações
GATEWAY_URL="http://localhost:8083"
TIMEOUT=10

# Função para imprimir cabeçalho
print_header() {
    echo -e "${WHITE}========================================${NC}"
    echo -e "${WHITE}  🚀 TESTE DO SPRING CLOUD GATEWAY 🚀${NC}"
    echo -e "${WHITE}========================================${NC}"
    echo ""
}

# Função para imprimir seção
print_section() {
    echo -e "${CYAN}📋 $1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..50})${NC}"
}

# Função para imprimir teste
print_test() {
    echo -e "${YELLOW}🔍 Testando: $1${NC}"
    echo -e "${BLUE}URL: $2${NC}"
}

# Função para imprimir resultado
print_result() {
    local status_code=$1
    local response=$2
    
    if [ $status_code -eq 200 ]; then
        echo -e "${GREEN}✅ Status: $status_code (SUCCESS)${NC}"
    else
        echo -e "${RED}❌ Status: $status_code (ERROR)${NC}"
    fi
    
    echo -e "${PURPLE}📄 Resposta:${NC}"
    echo "$response"
    echo ""
}

# Função para fazer requisição
make_request() {
    local url=$1
    local description=$2
    
    print_test "$description" "$url"
    
    response=$(curl -s -w "\n%{http_code}" --connect-timeout $TIMEOUT "$url")
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    print_result "$status_code" "$body"
}

# Função para testar fallback
test_fallback() {
    local service=$1
    local fallback_url="$GATEWAY_URL/fallback/$service"
    
    print_test "Fallback $service" "$fallback_url"
    
    response=$(curl -s -w "\n%{http_code}" --connect-timeout $TIMEOUT "$fallback_url")
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    print_result "$status_code" "$body"
}

# Função para verificar se o gateway está rodando
check_gateway() {
    echo -e "${YELLOW}🔍 Verificando se o gateway está rodando...${NC}"
    
    if curl -s --connect-timeout 5 "$GATEWAY_URL/actuator/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Gateway está rodando em $GATEWAY_URL${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}❌ Gateway não está rodando em $GATEWAY_URL${NC}"
        echo -e "${YELLOW}💡 Certifique-se de que o gateway está iniciado:${NC}"
        echo -e "${WHITE}   ./gradlew bootRun${NC}"
        echo -e "${WHITE}   ou${NC}"
        echo -e "${WHITE}   docker-compose up --build${NC}"
        echo ""
        return 1
    fi
}

# Função principal
main() {
    print_header
    
    # Verificar se o gateway está rodando
    if ! check_gateway; then
        exit 1
    fi
    
    # Testar rotas diretas
    print_section "ROTAS DIRETAS"
    
    make_request "$GATEWAY_URL/users" "Lista de usuários"
    make_request "$GATEWAY_URL/users/1" "Usuário específico (ID: 1)"
    make_request "$GATEWAY_URL/products" "Lista de produtos"
    make_request "$GATEWAY_URL/products/1" "Produto específico (ID: 1)"
    make_request "$GATEWAY_URL/orders" "Lista de pedidos"
    make_request "$GATEWAY_URL/orders/1" "Pedido específico (ID: 1)"
    
    # Testar rotas com prefixo
    print_section "ROTAS COM PREFIXO"
    
    make_request "$GATEWAY_URL/user-service/users" "Usuários via prefixo"
    make_request "$GATEWAY_URL/user-service/users/1" "Usuário específico via prefixo"
    make_request "$GATEWAY_URL/product-service/products" "Produtos via prefixo"
    make_request "$GATEWAY_URL/product-service/products/1" "Produto específico via prefixo"
    make_request "$GATEWAY_URL/order-service/orders" "Pedidos via prefixo"
    make_request "$GATEWAY_URL/order-service/orders/1" "Pedido específico via prefixo"
    
    # Testar fallbacks
    print_section "FALLBACKS"
    
    test_fallback "user"
    test_fallback "product"
    test_fallback "order"
    
    # Testar endpoints de monitoramento
    print_section "MONITORAMENTO"
    
    make_request "$GATEWAY_URL/actuator/health" "Health Check"
    make_request "$GATEWAY_URL/actuator/gateway/routes" "Rotas do Gateway"
    
    # Resumo final
    echo -e "${WHITE}========================================${NC}"
    echo -e "${WHITE}  🎉 TESTE CONCLUÍDO COM SUCESSO! 🎉${NC}"
    echo -e "${WHITE}========================================${NC}"
    echo ""
    echo -e "${CYAN}💡 Dicas:${NC}"
    echo -e "${WHITE}   • Para ver logs detalhados: ./gradlew bootRun${NC}"
    echo -e "${WHITE}   • Para parar o gateway: Ctrl+C${NC}"
    echo -e "${WHITE}   • Para testar com Docker: docker-compose up --build${NC}"
    echo ""
}

# Executar função principal
main
