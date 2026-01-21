#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

if [ ! -d "$RESULTS_DIR" ]; then
    echo "Erro: Diretório de resultados não encontrado: $RESULTS_DIR"
    echo "Execute primeiro o script run-benchmark.sh"
    exit 1
fi

LATEST_GATEWAY=$(find "$RESULTS_DIR" -name "gateway_*.csv" | sort -r | head -1)
LATEST_NATIVE=$(find "$RESULTS_DIR" -name "gateway-native_*.csv" | sort -r | head -1)
LATEST_TOMCAT=$(find "$RESULTS_DIR" -name "gateway-tomcat_*.csv" | sort -r | head -1)

if [ -z "$LATEST_GATEWAY" ] || [ -z "$LATEST_NATIVE" ] || [ -z "$LATEST_TOMCAT" ]; then
    echo "Erro: Nem todos os resultados foram encontrados"
    echo "Gateway: ${LATEST_GATEWAY:-NÃO ENCONTRADO}"
    echo "Native: ${LATEST_NATIVE:-NÃO ENCONTRADO}"
    echo "Tomcat: ${LATEST_TOMCAT:-NÃO ENCONTRADO}"
    exit 1
fi

echo "=========================================="
echo "  Comparação de Resultados"
echo "=========================================="
echo ""
echo "Gateway (Netty):    $LATEST_GATEWAY"
echo "Gateway Native:    $LATEST_NATIVE"
echo "Gateway Tomcat:    $LATEST_TOMCAT"
echo ""

get_global_throughput() {
    local file="$1"
    if [ -f "$file" ]; then
        local value=$(awk -F',' '/^GLOBAL,/ {print $13}' "$file" | head -1 | tr -d ' ')
        if [ -z "$value" ] || [ "$value" = "" ]; then
            echo "0"
        else
            echo "$value"
        fi
    else
        echo "0"
    fi
}

get_global_mean() {
    local file="$1"
    if [ -f "$file" ]; then
        local value=$(awk -F',' '/^GLOBAL,/ {print $5}' "$file" | head -1 | tr -d ' ')
        if [ -z "$value" ] || [ "$value" = "" ]; then
            echo "0"
        else
            echo "$value"
        fi
    else
        echo "0"
    fi
}

get_global_p95() {
    local file="$1"
    if [ -f "$file" ]; then
        local value=$(awk -F',' '/^GLOBAL,/ {print $9}' "$file" | head -1 | tr -d ' ')
        if [ -z "$value" ] || [ "$value" = "" ]; then
            echo "0"
        else
            echo "$value"
        fi
    else
        echo "0"
    fi
}

get_global_success_rate() {
    local file="$1"
    if [ -f "$file" ]; then
        local success=$(awk -F',' '/^GLOBAL,/ {print $11}' "$file" | head -1)
        local failure=$(awk -F',' '/^GLOBAL,/ {print $12}' "$file" | head -1)
        local total=$((success + failure))
        if [ $total -gt 0 ]; then
            echo "scale=2; $success * 100 / $total" | bc
        else
            echo "0"
        fi
    else
        echo "0"
    fi
}

THROUGHPUT_GATEWAY=$(get_global_throughput "$LATEST_GATEWAY")
THROUGHPUT_NATIVE=$(get_global_throughput "$LATEST_NATIVE")
THROUGHPUT_TOMCAT=$(get_global_throughput "$LATEST_TOMCAT")

MEAN_GATEWAY=$(get_global_mean "$LATEST_GATEWAY")
MEAN_NATIVE=$(get_global_mean "$LATEST_NATIVE")
MEAN_TOMCAT=$(get_global_mean "$LATEST_TOMCAT")

P95_GATEWAY=$(get_global_p95 "$LATEST_GATEWAY")
P95_NATIVE=$(get_global_p95 "$LATEST_NATIVE")
P95_TOMCAT=$(get_global_p95 "$LATEST_TOMCAT")

SUCCESS_GATEWAY=$(get_global_success_rate "$LATEST_GATEWAY")
SUCCESS_NATIVE=$(get_global_success_rate "$LATEST_NATIVE")
SUCCESS_TOMCAT=$(get_global_success_rate "$LATEST_TOMCAT")

echo "=========================================="
echo "  Métricas de Throughput (req/s)"
echo "=========================================="
printf "%-20s %15s\n" "Gateway (Netty):" "$THROUGHPUT_GATEWAY"
printf "%-20s %15s\n" "Gateway Native:" "$THROUGHPUT_NATIVE"
printf "%-20s %15s\n" "Gateway Tomcat:" "$THROUGHPUT_TOMCAT"
echo ""

MAX_THROUGHPUT=$(echo -e "$THROUGHPUT_GATEWAY\n$THROUGHPUT_NATIVE\n$THROUGHPUT_TOMCAT" | grep -v "^$" | sort -n | tail -1)

if [ -z "$MAX_THROUGHPUT" ] || [ "$MAX_THROUGHPUT" = "0" ]; then
    WINNER="N/A (sem dados)"
else
    if [ "$(echo "$THROUGHPUT_GATEWAY >= $MAX_THROUGHPUT" | bc -l 2>/dev/null)" -eq 1 ] 2>/dev/null; then
        WINNER="Gateway (Netty)"
    elif [ "$(echo "$THROUGHPUT_NATIVE >= $MAX_THROUGHPUT" | bc -l 2>/dev/null)" -eq 1 ] 2>/dev/null; then
        WINNER="Gateway Native"
    else
        WINNER="Gateway Tomcat"
    fi
fi

echo "🏆 Melhor Throughput: $WINNER ($MAX_THROUGHPUT req/s)"
echo ""

echo "=========================================="
echo "  Tempo de Resposta Médio (ms)"
echo "=========================================="
printf "%-20s %15s\n" "Gateway (Netty):" "$MEAN_GATEWAY"
printf "%-20s %15s\n" "Gateway Native:" "$MEAN_NATIVE"
printf "%-20s %15s\n" "Gateway Tomcat:" "$MEAN_TOMCAT"
echo ""

echo "=========================================="
echo "  Percentil 95 (ms)"
echo "=========================================="
printf "%-20s %15s\n" "Gateway (Netty):" "$P95_GATEWAY"
printf "%-20s %15s\n" "Gateway Native:" "$P95_NATIVE"
printf "%-20s %15s\n" "Gateway Tomcat:" "$P95_TOMCAT"
echo ""

echo "=========================================="
echo "  Taxa de Sucesso (%)"
echo "=========================================="
printf "%-20s %15.2f%%\n" "Gateway (Netty):" "$SUCCESS_GATEWAY"
printf "%-20s %15.2f%%\n" "Gateway Native:" "$SUCCESS_NATIVE"
printf "%-20s %15.2f%%\n" "Gateway Tomcat:" "$SUCCESS_TOMCAT"
echo ""

echo "=========================================="
echo "  Resumo"
echo "=========================================="
echo ""
echo "Melhor Throughput: $WINNER"
echo ""

COMPARISON_FILE="$RESULTS_DIR/comparison_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "Comparação de Benchmark - $(date)"
    echo "=========================================="
    echo ""
    echo "Throughput (req/s):"
    echo "  Gateway (Netty): $THROUGHPUT_GATEWAY"
    echo "  Gateway Native: $THROUGHPUT_NATIVE"
    echo "  Gateway Tomcat: $THROUGHPUT_TOMCAT"
    echo ""
    echo "Tempo de Resposta Médio (ms):"
    echo "  Gateway (Netty): $MEAN_GATEWAY"
    echo "  Gateway Native: $MEAN_NATIVE"
    echo "  Gateway Tomcat: $MEAN_TOMCAT"
    echo ""
    echo "Percentil 95 (ms):"
    echo "  Gateway (Netty): $P95_GATEWAY"
    echo "  Gateway Native: $P95_NATIVE"
    echo "  Gateway Tomcat: $P95_TOMCAT"
    echo ""
    echo "Taxa de Sucesso (%):"
    echo "  Gateway (Netty): $SUCCESS_GATEWAY"
    echo "  Gateway Native: $SUCCESS_NATIVE"
    echo "  Gateway Tomcat: $SUCCESS_TOMCAT"
    echo ""
    echo "Vencedor: $WINNER"
} > "$COMPARISON_FILE"

echo "Comparação detalhada salva em: $COMPARISON_FILE"
echo ""

