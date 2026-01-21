#!/bin/bash

GATLING_REPORT_DIR="$1"
OUTPUT_FILE="$2"

if [ -z "$GATLING_REPORT_DIR" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Uso: $0 <diretorio_relatorio_gatling> <arquivo_saida>"
    exit 1
fi

if [ ! -d "$GATLING_REPORT_DIR" ]; then
    echo "Erro: Diretório $GATLING_REPORT_DIR não encontrado"
    exit 1
fi

GLOBAL_STATS_JSON=$(find "$GATLING_REPORT_DIR" -name "global_stats.json" | head -1)

if [ -z "$GLOBAL_STATS_JSON" ]; then
    echo "Erro: global_stats.json não encontrado em $GATLING_REPORT_DIR"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Erro: jq não está instalado. Instale com: sudo apt install jq"
    exit 1
fi

{
    echo "REQUEST_NAME,COUNT,MIN,MAX,MEAN,STD_DEV,P50,P75,P95,P99,SUCCESS,FAILURE,THROUGHPUT"
    
    TOTAL=$(jq -r '.numberOfRequests.total' "$GLOBAL_STATS_JSON")
    OK=$(jq -r '.numberOfRequests.ok' "$GLOBAL_STATS_JSON")
    KO=$(jq -r '.numberOfRequests.ko' "$GLOBAL_STATS_JSON")
    MIN=$(jq -r '.minResponseTime.total' "$GLOBAL_STATS_JSON")
    MAX=$(jq -r '.maxResponseTime.total' "$GLOBAL_STATS_JSON")
    MEAN=$(jq -r '.meanResponseTime.total' "$GLOBAL_STATS_JSON")
    STD_DEV=$(jq -r '.standardDeviation.total' "$GLOBAL_STATS_JSON")
    P50=$(jq -r '.percentiles1.total' "$GLOBAL_STATS_JSON")
    P75=$(jq -r '.percentiles2.total' "$GLOBAL_STATS_JSON")
    P95=$(jq -r '.percentiles3.total' "$GLOBAL_STATS_JSON")
    P99=$(jq -r '.percentiles4.total' "$GLOBAL_STATS_JSON")
    
    DURATION=$(jq -r '.meanNumberOfRequestsPerSecond.duration' "$GLOBAL_STATS_JSON" 2>/dev/null || echo "0")
    if [ "$DURATION" = "0" ] || [ -z "$DURATION" ]; then
        THROUGHPUT=$(jq -r '.meanNumberOfRequestsPerSecond.total' "$GLOBAL_STATS_JSON" 2>/dev/null || echo "0")
    else
        THROUGHPUT=$(echo "scale=2; $TOTAL / $DURATION * 1000" | bc 2>/dev/null || echo "0")
    fi
    
    if [ -z "$THROUGHPUT" ] || [ "$THROUGHPUT" = "null" ] || [ "$THROUGHPUT" = "0" ]; then
        MEAN_REQ_PER_SEC=$(jq -r '.meanNumberOfRequestsPerSecond.total' "$GLOBAL_STATS_JSON" 2>/dev/null || echo "0")
        if [ "$MEAN_REQ_PER_SEC" != "null" ] && [ "$MEAN_REQ_PER_SEC" != "0" ]; then
            THROUGHPUT="$MEAN_REQ_PER_SEC"
        fi
    fi
    
    echo "GLOBAL,$TOTAL,$MIN,$MAX,$MEAN,$STD_DEV,$P50,$P75,$P95,$P99,$OK,$KO,$THROUGHPUT"
} > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ] || [ "$(wc -l < "$OUTPUT_FILE")" -le 1 ]; then
    echo "Aviso: Nenhuma métrica foi extraída. Verificando formato do arquivo..."
    echo "Conteúdo do global_stats.json:"
    head -20 "$GLOBAL_STATS_JSON"
    exit 1
fi

echo "Métricas extraídas para: $OUTPUT_FILE"

