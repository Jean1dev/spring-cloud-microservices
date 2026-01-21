#!/bin/bash

echo "=== Spring Cloud Gateway Performance Tests ==="
echo ""

if ! command -v java &> /dev/null; then
    echo "✗ Java não encontrado. Por favor, instale o Java 21:"
    echo "   sudo apt install openjdk-21-jdk"
    echo "   Ou configure JAVA_HOME para apontar para sua instalação do Java."
    exit 1
fi

# Verificar se o Gateway está rodando
echo "Verificando se o Gateway está rodando..."
if curl -s http://localhost:8083/actuator/health > /dev/null; then
    echo "✓ Gateway está rodando em http://localhost:8083"
else
    echo "✗ Gateway não está rodando. Inicie o Gateway antes de executar os testes."
    echo "Execute: ./gradlew bootRun"
    exit 1
fi

echo ""
echo "Compilando testes Gatling..."
./gradlew compileGatlingScala
if [ $? -ne 0 ]; then
    echo "✗ Falha ao compilar testes Gatling"
    exit 1
fi
echo "✓ Testes compilados com sucesso"

echo ""
echo "Escolha o tipo de teste:"
echo "1. Teste de Performance Básico (GatewayPerformanceTest)"
echo "2. Teste de Carga Pesada (HeavyLoadTest)"
echo "3. Teste de Circuit Breaker (CircuitBreakerTest)"
echo "4. Executar todos os testes"
echo ""

read -p "Digite sua escolha (1-4): " choice

case $choice in
    1)
        echo "Executando GatewayPerformanceTest..."
        ./gradlew gatlingRun --simulation=com.example.gateway.performance.GatewayPerformanceTest
        ;;
    2)
        echo "Executando HeavyLoadTest..."
        ./gradlew gatlingRun --simulation=com.example.gateway.performance.HeavyLoadTest
        ;;
    3)
        echo "Executando CircuitBreakerTest..."
        ./gradlew gatlingRun --simulation=com.example.gateway.performance.CircuitBreakerTest
        ;;
    4)
        echo "Executando todos os testes..."
        ./gradlew gatlingRun
        ;;
    *)
        echo "Opção inválida. Saindo..."
        exit 1
        ;;
esac

echo ""
echo "=== Testes concluídos! ==="
echo "Relatórios disponíveis em: build/reports/gatling/"
echo "Para visualizar os relatórios HTML, abra o arquivo index.html na pasta do teste correspondente."
