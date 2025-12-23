#!/bin/bash

echo "=========================================="
echo "  Verificação de Pré-requisitos"
echo "=========================================="
echo ""

ERRORS=0

if ! command -v docker &> /dev/null; then
    echo "✗ Docker não está instalado"
    echo "  Instale com: sudo apt install docker.io"
    ERRORS=$((ERRORS + 1))
else
    DOCKER_VERSION=$(docker --version)
    echo "✓ Docker instalado: $DOCKER_VERSION"
    
    if ! docker info &> /dev/null; then
        echo "✗ Docker não está rodando ou você não tem permissão"
        echo "  Execute: sudo systemctl start docker"
        echo "  Ou adicione seu usuário ao grupo docker: sudo usermod -aG docker $USER"
        ERRORS=$((ERRORS + 1))
    else
        echo "✓ Docker está rodando"
    fi
fi

if ! command -v java &> /dev/null; then
    echo "✗ Java não está instalado"
    echo "  Instale com: sudo apt install openjdk-21-jdk"
    ERRORS=$((ERRORS + 1))
else
    JAVA_VERSION=$(java -version 2>&1 | head -1)
    echo "✓ Java instalado: $JAVA_VERSION"
fi

if ! command -v bc &> /dev/null; then
    echo "✗ bc não está instalado (necessário para comparação de resultados)"
    echo "  Instale com: sudo apt install bc"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ bc instalado"
fi

if ! command -v jq &> /dev/null; then
    echo "✗ jq não está instalado (necessário para extração de métricas)"
    echo "  Instale com: sudo apt install jq"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ jq instalado"
fi

if command -v docker &> /dev/null && docker compose version &> /dev/null 2>/dev/null; then
    COMPOSE_VERSION=$(docker compose version)
    echo "✓ Docker Compose instalado: $COMPOSE_VERSION"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version)
    echo "✓ Docker Compose instalado: $COMPOSE_VERSION"
else
    echo "✗ Docker Compose não está instalado"
    ERRORS=$((ERRORS + 1))
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$SCRIPT_DIR/../gateway" ]; then
    echo "✗ Diretório gateway não encontrado"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ Diretório gateway encontrado"
fi

if [ ! -d "$SCRIPT_DIR/../gateway java native" ]; then
    echo "✗ Diretório 'gateway java native' não encontrado"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ Diretório 'gateway java native' encontrado"
fi

if [ ! -d "$SCRIPT_DIR/../gateway tomcat" ]; then
    echo "✗ Diretório 'gateway tomcat' não encontrado"
    ERRORS=$((ERRORS + 1))
else
    echo "✓ Diretório 'gateway tomcat' encontrado"
fi

echo ""
echo "=========================================="
if [ $ERRORS -eq 0 ]; then
    echo "✓ Todos os pré-requisitos estão instalados!"
    echo "  Você pode executar: ./run-benchmark.sh"
    exit 0
else
    echo "✗ Faltam $ERRORS pré-requisito(s)"
    echo "  Corrija os problemas acima antes de executar o benchmark"
    exit 1
fi

