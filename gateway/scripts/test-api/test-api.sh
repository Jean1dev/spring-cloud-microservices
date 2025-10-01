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

# Função para mostrar uso
show_usage() {
    echo -e "${WHITE}Uso: $0 [API] [ENDPOINT]${NC}"
    echo ""
    echo -e "${CYAN}APIs disponíveis:${NC}"
    echo -e "${YELLOW}  user     - API de usuários${NC}"
    echo -e "${YELLOW}  product  - API de produtos${NC}"
    echo -e "${YELLOW}  order    - API de pedidos${NC}"
    echo ""
    echo -e "${CYAN}Endpoints disponíveis:${NC}"
    echo -e "${YELLOW}  list     - Lista todos os itens${NC}"
    echo -e "${YELLOW}  get      - Busca item específico (ID: 1)${NC}"
    echo -e "${YELLOW}  fallback - Testa fallback${NC}"
    echo ""
    echo -e "${CYAN}Exemplos:${NC}"
    echo -e "${WHITE}  $0 user list${NC}"
    echo -e "${WHITE}  $0 product get${NC}"
    echo -e "${WHITE}  $0 order fallback${NC}"
    echo ""
}

# Função para fazer requisição
make_request() {
    local url=$1
    local description=$2
    
    echo -e "${YELLOW}🔍 Testando: $description${NC}"
    echo -e "${BLUE}URL: $url${NC}"
    
    response=$(curl -s -w "\n%{http_code}" --connect-timeout $TIMEOUT "$url")
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ $status_code -eq 200 ]; then
        echo -e "${GREEN}✅ Status: $status_code (SUCCESS)${NC}"
    else
        echo -e "${RED}❌ Status: $status_code (ERROR)${NC}"
    fi
    
    echo -e "${PURPLE}📄 Resposta:${NC}"
    echo "$body" | jq . 2>/dev/null || echo "$body"
    echo ""
}

# Função para testar API específica
test_api() {
    local api=$1
    local endpoint=$2
    
    case $api in
        "user")
            case $endpoint in
                "list")
                    make_request "$GATEWAY_URL/users" "Lista de usuários"
                    ;;
                "get")
                    make_request "$GATEWAY_URL/users/1" "Usuário específico (ID: 1)"
                    ;;
                "fallback")
                    make_request "$GATEWAY_URL/fallback/user" "Fallback de usuários"
                    ;;
                *)
                    echo -e "${RED}❌ Endpoint inválido para user: $endpoint${NC}"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        "product")
            case $endpoint in
                "list")
                    make_request "$GATEWAY_URL/products" "Lista de produtos"
                    ;;
                "get")
                    make_request "$GATEWAY_URL/products/1" "Produto específico (ID: 1)"
                    ;;
                "fallback")
                    make_request "$GATEWAY_URL/fallback/product" "Fallback de produtos"
                    ;;
                *)
                    echo -e "${RED}❌ Endpoint inválido para product: $endpoint${NC}"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        "order")
            case $endpoint in
                "list")
                    make_request "$GATEWAY_URL/orders" "Lista de pedidos"
                    ;;
                "get")
                    make_request "$GATEWAY_URL/orders/1" "Pedido específico (ID: 1)"
                    ;;
                "fallback")
                    make_request "$GATEWAY_URL/fallback/order" "Fallback de pedidos"
                    ;;
                *)
                    echo -e "${RED}❌ Endpoint inválido para order: $endpoint${NC}"
                    show_usage
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo -e "${RED}❌ API inválida: $api${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Função para verificar se o gateway está rodando
check_gateway() {
    if curl -s --connect-timeout 5 "$GATEWAY_URL/actuator/health" > /dev/null 2>&1; then
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
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    
    if [ $# -eq 1 ]; then
        show_usage
        exit 1
    fi
    
    local api=$1
    local endpoint=$2
    
    echo -e "${WHITE}🚀 Testando API: $api - Endpoint: $endpoint${NC}"
    echo ""
    
    # Verificar se o gateway está rodando
    if ! check_gateway; then
        exit 1
    fi
    
    # Testar API específica
    test_api "$api" "$endpoint"
}

# Executar função principal
main "$@"
