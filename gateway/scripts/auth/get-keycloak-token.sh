#!/bin/bash

# =============================================================================
# SCRIPT PARA OBTER TOKEN DO KEYCLOAK
# =============================================================================
# Este script obtém um token de acesso do Keycloak para autenticação
# no Gateway Spring Cloud

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
KEYCLOAK_HOST="http://localhost:8084"
REALM="gateway-client"
CLIENT_ID="gateway-client"
CLIENT_SECRET="wiUc08ZfgTD0eFXbt5c3hRBGSBwi6WAp"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"

# -----------------------------------------------------------------------------
# CORES PARA OUTPUT
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# FUNÇÕES AUXILIARES
# -----------------------------------------------------------------------------
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# -----------------------------------------------------------------------------
# VERIFICAÇÃO DE DEPENDÊNCIAS
# -----------------------------------------------------------------------------
check_dependencies() {
    print_info "Verificando dependências..."
    
    if ! command -v curl &> /dev/null; then
        print_error "curl não está instalado. Instale o curl para continuar."
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        print_warning "jq não está instalado. A saída do token não será formatada."
        JQ_AVAILABLE=false
    else
        JQ_AVAILABLE=true
    fi
    
    print_success "Dependências verificadas"
}

# -----------------------------------------------------------------------------
# VERIFICAÇÃO DE CONECTIVIDADE
# -----------------------------------------------------------------------------
check_keycloak_connectivity() {
    print_info "Verificando conectividade com Keycloak..."
    
    if curl -s --connect-timeout 10 "$KEYCLOAK_HOST/realms/$REALM" > /dev/null; then
        print_success "Keycloak está acessível"
    else
        print_error "Não foi possível conectar ao Keycloak em $KEYCLOAK_HOST"
        print_info "Verifique se o Keycloak está rodando: docker-compose up keycloak"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# OBTENÇÃO DO TOKEN
# -----------------------------------------------------------------------------
get_token() {
    print_info "Obtendo token do Keycloak..."
    
    # URL do endpoint de token
    TOKEN_URL="$KEYCLOAK_HOST/realms/$REALM/protocol/openid-connect/token"
    
    # Dados para autenticação
    TOKEN_DATA="grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
    
    # Fazer a requisição
    RESPONSE=$(curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$TOKEN_DATA" \
        "$TOKEN_URL")
    
    # Verificar se a resposta contém erro
    if echo "$RESPONSE" | grep -q "error"; then
        print_error "Erro ao obter token:"
        if [ "$JQ_AVAILABLE" = true ]; then
            echo "$RESPONSE" | jq .
        else
            echo "$RESPONSE"
        fi
        exit 1
    fi
    
    # Extrair o token
    if [ "$JQ_AVAILABLE" = true ]; then
        ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
        TOKEN_TYPE=$(echo "$RESPONSE" | jq -r '.token_type')
        EXPIRES_IN=$(echo "$RESPONSE" | jq -r '.expires_in')
    else
        ACCESS_TOKEN=$(echo "$RESPONSE" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
        TOKEN_TYPE=$(echo "$RESPONSE" | sed -n 's/.*"token_type":"\([^"]*\)".*/\1/p')
        EXPIRES_IN=$(echo "$RESPONSE" | sed -n 's/.*"expires_in":\([^,}]*\).*/\1/p')
    fi
    
    if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        print_error "Não foi possível extrair o token da resposta"
        echo "Resposta completa:"
        echo "$RESPONSE"
        exit 1
    fi
    
    print_success "Token obtido com sucesso!"
    echo
    print_info "Informações do token:"
    echo "  Tipo: $TOKEN_TYPE"
    echo "  Expira em: $EXPIRES_IN segundos"
    echo
}

# -----------------------------------------------------------------------------
# EXIBIÇÃO DO TOKEN
# -----------------------------------------------------------------------------
display_token() {
    print_info "Token de acesso:"
    echo
    echo "Authorization: Bearer $ACCESS_TOKEN"
    echo
    print_info "Para usar em requisições curl:"
    echo "curl -H \"Authorization: Bearer $ACCESS_TOKEN\" http://localhost:8083/api/users"
    echo
}

# -----------------------------------------------------------------------------
# SALVAR TOKEN EM ARQUIVO
# -----------------------------------------------------------------------------
save_token() {
    if [ "$1" = "--save" ] || [ "$1" = "-s" ]; then
        TOKEN_FILE="keycloak-token.txt"
        echo "$ACCESS_TOKEN" > "$TOKEN_FILE"
        print_success "Token salvo em $TOKEN_FILE"
    fi
}

# -----------------------------------------------------------------------------
# DECODIFICAR TOKEN (JWT)
# -----------------------------------------------------------------------------
decode_token() {
    if [ "$1" = "--decode" ] || [ "$1" = "-d" ]; then
        print_info "Decodificando token JWT..."
        echo
        
        # Separar as partes do JWT
        IFS='.' read -r HEADER PAYLOAD SIGNATURE <<< "$ACCESS_TOKEN"
        
        # Decodificar header
        echo "Header:"
        echo "$HEADER" | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "$HEADER" | base64 -d 2>/dev/null
        echo
        
        # Decodificar payload
        echo "Payload:"
        echo "$PAYLOAD" | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "$PAYLOAD" | base64 -d 2>/dev/null
        echo
    fi
}

# -----------------------------------------------------------------------------
# FUNÇÃO PRINCIPAL
# -----------------------------------------------------------------------------
main() {
    echo "============================================================================="
    echo "                    SCRIPT DE OBTENÇÃO DE TOKEN KEYCLOAK"
    echo "============================================================================="
    echo
    
    check_dependencies
    check_keycloak_connectivity
    get_token
    display_token
    save_token "$1"
    decode_token "$1"
    
    echo
    print_success "Script executado com sucesso!"
}

# -----------------------------------------------------------------------------
# AJUDA
# -----------------------------------------------------------------------------
show_help() {
    echo "Uso: $0 [OPÇÕES]"
    echo
    echo "Opções:"
    echo "  -s, --save     Salva o token em um arquivo (keycloak-token.txt)"
    echo "  -d, --decode   Decodifica e exibe o conteúdo do token JWT"
    echo "  -h, --help     Exibe esta ajuda"
    echo
    echo "Exemplos:"
    echo "  $0                    # Obtém e exibe o token"
    echo "  $0 --save            # Obtém e salva o token em arquivo"
    echo "  $0 --decode          # Obtém e decodifica o token"
    echo "  $0 --save --decode   # Obtém, salva e decodifica o token"
}

# -----------------------------------------------------------------------------
# PROCESSAMENTO DE ARGUMENTOS
# -----------------------------------------------------------------------------
case "$1" in
    -h|--help)
        show_help
        exit 0
        ;;
    *)
        main "$1"
        ;;
esac
