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

# Função para imprimir cabeçalho
print_header() {
    echo -e "${WHITE}========================================${NC}"
    echo -e "${WHITE}  🎬 DEMONSTRAÇÃO DO GATEWAY 🎬${NC}"
    echo -e "${WHITE}========================================${NC}"
    echo ""
}

# Função para imprimir seção
print_section() {
    echo -e "${CYAN}📋 $1${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..50})${NC}"
}

# Função para executar comando
run_command() {
    local description=$1
    local command=$2
    
    echo -e "${YELLOW}🔍 $description${NC}"
    echo -e "${BLUE}Comando: $command${NC}"
    echo ""
    
    eval "$command"
    
    echo ""
    echo -e "${PURPLE}Pressione Enter para continuar...${NC}"
    read -r
    echo ""
}

# Função principal
main() {
    print_header
    
    echo -e "${WHITE}Este script demonstra como usar os scripts de teste do gateway.${NC}"
    echo -e "${WHITE}Certifique-se de que o gateway está rodando antes de executar.${NC}"
    echo ""
    
    print_section "1. TESTE COMPLETO DO GATEWAY"
    run_command "Executando teste completo com formatação colorida" "./test-gateway.sh"
    
    print_section "2. TESTE DE API ESPECÍFICA - USUÁRIOS"
    run_command "Testando lista de usuários" "./test-api.sh user list"
    run_command "Testando usuário específico" "./test-api.sh user get"
    run_command "Testando fallback de usuários" "./test-api.sh user fallback"
    
    print_section "3. TESTE DE API ESPECÍFICA - PRODUTOS"
    run_command "Testando lista de produtos" "./test-api.sh product list"
    run_command "Testando produto específico" "./test-api.sh product get"
    run_command "Testando fallback de produtos" "./test-api.sh product fallback"
    
    print_section "4. TESTE DE API ESPECÍFICA - PEDIDOS"
    run_command "Testando lista de pedidos" "./test-api.sh order list"
    run_command "Testando pedido específico" "./test-api.sh order get"
    run_command "Testando fallback de pedidos" "./test-api.sh order fallback"
    
    print_section "5. TESTE SIMPLES (SEM JQ)"
    run_command "Executando teste simples" "./test-gateway-simple.sh"
    
    echo -e "${WHITE}========================================${NC}"
    echo -e "${WHITE}  🎉 DEMONSTRAÇÃO CONCLUÍDA! 🎉${NC}"
    echo -e "${WHITE}========================================${NC}"
    echo ""
    echo -e "${CYAN}💡 Dicas:${NC}"
    echo -e "${WHITE}   • Use ./test-gateway.sh para teste completo${NC}"
    echo -e "${WHITE}   • Use ./test-api.sh [api] [endpoint] para testes específicos${NC}"
    echo -e "${WHITE}   • Use ./test-gateway-simple.sh se não tiver jq instalado${NC}"
    echo -e "${WHITE}   • Use ../../scripts/run.sh test-api [script] para executar via script principal${NC}"
    echo ""
}

# Executar função principal
main
