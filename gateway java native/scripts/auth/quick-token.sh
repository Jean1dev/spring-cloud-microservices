#!/bin/bash

# Script rápido para obter token do Keycloak
# Uso: ./quick-token.sh

KEYCLOAK_HOST="http://localhost:8084"
REALM="gateway-client"
CLIENT_ID="gateway-client"
CLIENT_SECRET="wiUc08ZfgTD0eFXbt5c3hRBGSBwi6WAp"

TOKEN_URL="$KEYCLOAK_HOST/realms/$REALM/protocol/openid-connect/token"

echo "Obtendo token do Keycloak..."

TOKEN_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
    "$TOKEN_URL")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "Erro ao obter token:"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

echo "Token obtido:"
echo "Bearer $ACCESS_TOKEN"
echo
echo "Para testar o gateway:"
echo "curl -H \"Authorization: Bearer $ACCESS_TOKEN\" http://localhost:8083/users"
