#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK_DIR="$SCRIPT_DIR"
RESULTS_DIR="$BENCHMARK_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

GATEWAYS=("gateway" "gateway-native" "gateway-tomcat")
GATEWAY_PATHS=("gateway" "gateway java native" "gateway tomcat")
GATEWAY_NAMES=("Gateway (Netty)" "Gateway Native" "Gateway Tomcat")

mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  Benchmark de Throughput de IO"
echo "=========================================="
echo ""
echo "Recursos limitados:"
echo "  - CPU: 1.5 cores"
echo "  - Memória: 500MB"
echo ""
echo "Resultados serão salvos em: $RESULTS_DIR"
echo ""

if ! command -v docker &> /dev/null; then
    echo "Erro: Docker não está instalado"
    exit 1
fi

if ! command -v java &> /dev/null; then
    echo "Erro: Java não está instalado. Instale com: sudo apt install openjdk-21-jdk"
    exit 1
fi

for i in "${!GATEWAYS[@]}"; do
    GATEWAY="${GATEWAYS[$i]}"
    GATEWAY_PATH="${GATEWAY_PATHS[$i]}"
    GATEWAY_NAME="${GATEWAY_NAMES[$i]}"
    COMPOSE_FILE="$BENCHMARK_DIR/docker-compose.$GATEWAY.yml"
    GATEWAY_DIR="$SCRIPT_DIR/../$GATEWAY_PATH"
    
    echo "=========================================="
    echo "  Testando: $GATEWAY_NAME"
    echo "=========================================="
    echo ""
    
    if [ ! -f "$COMPOSE_FILE" ]; then
        echo "Erro: Arquivo $COMPOSE_FILE não encontrado"
        continue
    fi
    
    if [ ! -d "$GATEWAY_DIR" ]; then
        echo "Erro: Diretório $GATEWAY_DIR não encontrado"
        continue
    fi
    
    echo "1. Parando containers anteriores..."
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    else
        docker-compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    fi
    docker stop gateway-benchmark gateway-native-benchmark gateway-tomcat-benchmark 2>/dev/null || true
    docker rm gateway-benchmark gateway-native-benchmark gateway-tomcat-benchmark 2>/dev/null || true
    
    echo "2. Construindo e iniciando serviços..."
    cd "$BENCHMARK_DIR"
    
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        docker compose -f "$COMPOSE_FILE" up -d --build
    else
        docker-compose -f "$COMPOSE_FILE" up -d --build
    fi
    
    echo "3. Aguardando serviços ficarem prontos..."
    MAX_WAIT=120
    WAIT_TIME=0
    while [ $WAIT_TIME -lt $MAX_WAIT ]; do
        if curl -s http://localhost:8083/actuator/health > /dev/null 2>&1; then
            echo "   Gateway está pronto!"
            break
        fi
        echo "   Aguardando gateway... ($WAIT_TIME/$MAX_WAIT segundos)"
        sleep 5
        WAIT_TIME=$((WAIT_TIME + 5))
    done
    
    if [ $WAIT_TIME -ge $MAX_WAIT ]; then
        echo "   Erro: Gateway não ficou pronto a tempo"
        if command -v docker &> /dev/null && docker compose version &> /dev/null; then
            docker compose -f "$COMPOSE_FILE" logs gateway
        else
            docker-compose -f "$COMPOSE_FILE" logs gateway
        fi
        continue
    fi
    
    echo "4. Aguardando estabilização (10 segundos)..."
    sleep 10
    
    echo "5. Executando testes de performance..."
    cd "$GATEWAY_DIR"
    
    if [ ! -f "./gradlew" ]; then
        echo "   Erro: gradlew não encontrado em $GATEWAY_DIR"
        continue
    fi
    
    chmod +x ./gradlew
    
    echo "   Compilando testes Gatling..."
    ./gradlew compileGatlingScala --no-daemon || {
        echo "   Erro ao compilar testes"
        continue
    }
    
    echo "   Executando GatewayPerformanceTest..."
    ./gradlew gatlingRun --simulation=com.example.gateway.performance.GatewayPerformanceTest --no-daemon || {
        echo "   Erro ao executar testes"
        continue
    }
    
    echo "6. Extraindo métricas..."
    GATLING_REPORT=$(find "$GATEWAY_DIR/build/reports/gatling" -type d -name "*gatewayperformance*" | sort -r | head -1)
    
    if [ -z "$GATLING_REPORT" ]; then
        echo "   Erro: Relatório Gatling não encontrado"
        continue
    fi
    
    if ! command -v jq &> /dev/null; then
        echo "   Erro: jq não está instalado. Instale com: sudo apt install jq"
        continue
    fi
    
    RESULT_FILE="$RESULTS_DIR/${GATEWAY}_${TIMESTAMP}.csv"
    "$BENCHMARK_DIR/extract-metrics.sh" "$GATLING_REPORT" "$RESULT_FILE"
    
    echo "7. Copiando relatório HTML..."
    HTML_REPORT_DIR="$RESULTS_DIR/${GATEWAY}_${TIMESTAMP}_report"
    mkdir -p "$HTML_REPORT_DIR"
    cp -r "$GATLING_REPORT"/* "$HTML_REPORT_DIR/" 2>/dev/null || true
    
    echo "8. Parando containers..."
    cd "$BENCHMARK_DIR"
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        docker compose -f "$COMPOSE_FILE" down -v
    else
        docker-compose -f "$COMPOSE_FILE" down -v
    fi
    
    echo ""
    echo "✓ Teste concluído para $GATEWAY_NAME"
    echo "  Métricas: $RESULT_FILE"
    echo "  Relatório: $HTML_REPORT_DIR/index.html"
    echo ""
    
    sleep 5
done

echo "=========================================="
echo "  Benchmark Concluído!"
echo "=========================================="
echo ""
echo "Resultados salvos em: $RESULTS_DIR"
echo ""
echo "Para comparar os resultados, execute:"
echo "  $BENCHMARK_DIR/compare-results.sh"

