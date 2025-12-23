# Benchmark de Throughput de IO

Este diretório contém scripts e configurações para realizar benchmark de throughput de IO entre os três projetos de gateway:

- **Gateway (Netty)**: Spring Cloud Gateway padrão com Netty
- **Gateway Native**: Spring Cloud Gateway compilado nativamente com GraalVM
- **Gateway Tomcat**: Spring Cloud Gateway com Tomcat

## Objetivo

Comparar o throughput de IO de cada implementação de gateway sob condições controladas:
- **CPU limitado**: 1.5 cores
- **Memória limitada**: 500MB
- **Mesma carga de teste**: GatewayPerformanceTest do Gatling

## Estrutura

```
benchmark/
├── docker-compose.gateway.yml          # Configuração Docker para Gateway (Netty)
├── docker-compose.gateway-native.yml   # Configuração Docker para Gateway Native
├── docker-compose.gateway-tomcat.yml   # Configuração Docker para Gateway Tomcat
├── extract-metrics.sh                  # Script para extrair métricas dos relatórios Gatling
├── run-benchmark.sh                    # Script principal para executar o benchmark
├── compare-results.sh                  # Script para comparar resultados
├── README.md                           # Esta documentação
└── results/                            # Diretório com resultados (criado automaticamente)
```

## Pré-requisitos

1. **Docker** instalado e rodando
2. **Java 21** instalado
3. **Docker Compose** (geralmente incluído com Docker)
4. **bc** (calculadora para comparação de resultados): `sudo apt install bc`
5. **jq** (processador JSON para extração de métricas): `sudo apt install jq`

### Verificar Pré-requisitos

Execute o script de verificação antes de rodar o benchmark:

```bash
cd benchmark
./check-prerequisites.sh
```

Este script verifica se todos os pré-requisitos estão instalados e configurados corretamente.

## Como Executar

### Executar Benchmark Completo

Execute o script principal que irá:
1. Testar cada gateway sequencialmente
2. Subir os serviços com recursos limitados
3. Executar testes de performance
4. Extrair métricas
5. Salvar resultados

```bash
cd benchmark
chmod +x *.sh
./run-benchmark.sh
```

O script irá:
- Parar containers anteriores
- Construir e iniciar cada gateway com limites de recursos
- Aguardar o gateway ficar pronto
- Executar o teste `GatewayPerformanceTest` do Gatling
- Extrair métricas e salvar resultados
- Parar os containers

### Comparar Resultados

Após executar o benchmark, compare os resultados:

```bash
./compare-results.sh
```

Este script irá:
- Encontrar os resultados mais recentes de cada gateway
- Comparar métricas principais (throughput, tempo de resposta, taxa de sucesso)
- Identificar o vencedor
- Gerar um arquivo de comparação detalhado

## Recursos Limitados

Cada gateway é executado com os seguintes limites:

### Gateway
- **CPU**: 1.5 cores (limite), 0.5 cores (reserva)
- **Memória**: 500MB (limite), 250MB (reserva)

### Serviços Backend (user-service, product-service, order-service)
- **CPU**: 0.5 cores (limite), 0.25 cores (reserva)
- **Memória**: 200MB (limite), 100MB (reserva)

## Métricas Coletadas

O benchmark coleta as seguintes métricas:

1. **Throughput**: Requisições por segundo (req/s)
2. **Tempo de Resposta Médio**: Média de tempo de resposta em milissegundos
3. **Percentil 95 (P95)**: 95% das requisições respondem em menos de X ms
4. **Taxa de Sucesso**: Percentual de requisições bem-sucedidas
5. **Tempo de Resposta Mínimo/Máximo**
6. **Desvio Padrão**

## Resultados

Os resultados são salvos em `benchmark/results/` com a seguinte estrutura:

```
results/
├── gateway_YYYYMMDD_HHMMSS.csv              # Métricas CSV do Gateway (Netty)
├── gateway_YYYYMMDD_HHMMSS_report/          # Relatório HTML do Gateway (Netty)
├── gateway-native_YYYYMMDD_HHMMSS.csv        # Métricas CSV do Gateway Native
├── gateway-native_YYYYMMDD_HHMMSS_report/    # Relatório HTML do Gateway Native
├── gateway-tomcat_YYYYMMDD_HHMMSS.csv        # Métricas CSV do Gateway Tomcat
├── gateway-tomcat_YYYYMMDD_HHMMSS_report/    # Relatório HTML do Gateway Tomcat
└── comparison_YYYYMMDD_HHMMSS.txt            # Comparação detalhada
```

### Formato CSV

O arquivo CSV contém as seguintes colunas:
- `REQUEST_NAME`: Nome da requisição
- `COUNT`: Número total de requisições
- `MIN`: Tempo mínimo (ms)
- `MAX`: Tempo máximo (ms)
- `MEAN`: Tempo médio (ms)
- `STD_DEV`: Desvio padrão (ms)
- `P50`, `P75`, `P95`, `P99`: Percentis (ms)
- `SUCCESS`: Requisições bem-sucedidas
- `FAILURE`: Requisições falhadas
- `THROUGHPUT`: Requisições por segundo

A linha `GLOBAL` contém as métricas agregadas de todas as requisições.

## Teste de Performance

O benchmark utiliza o teste `GatewayPerformanceTest` do Gatling, que:

- **Cenários**: Health check, operações CRUD nos serviços
- **Carga**: 
  - 10 usuários simultâneos iniciais
  - Rampa até 50 usuários em 30 segundos
  - 20 usuários/seg por 60 segundos
  - Rampa de 10 a 30 usuários/seg em 30 segundos

## Interpretação dos Resultados

### Throughput (req/s)
- **Maior é melhor**: Indica quantas requisições o gateway consegue processar por segundo
- Esta é a métrica principal para comparar eficiência de IO

### Tempo de Resposta
- **Menor é melhor**: Indica a latência das requisições
- P95 é especialmente importante para entender a experiência do usuário

### Taxa de Sucesso
- **Maior é melhor**: Indica a confiabilidade do gateway
- Idealmente deve ser > 95%

## Troubleshooting

### Gateway não fica pronto
- Verifique os logs: `docker-compose -f docker-compose.gateway.yml logs gateway`
- Verifique se há portas em conflito
- Aumente o tempo de espera no script se necessário

### Erro ao compilar testes Gatling
- Verifique se o Java 21 está instalado: `java -version`
- Verifique se o Gradle tem permissão de execução: `chmod +x ../gateway/gradlew`

### Erro ao extrair métricas
- Verifique se o relatório Gatling foi gerado corretamente
- Verifique se o arquivo `simulation.log` existe no diretório do relatório

### Containers não param
- Execute manualmente: `docker-compose -f docker-compose.gateway.yml down -v`
- Force a remoção: `docker rm -f gateway-benchmark gateway-native-benchmark gateway-tomcat-benchmark`

## Limitações

1. **Ambiente**: Os resultados podem variar dependendo do hardware e sistema operacional
2. **Rede**: A latência de rede local pode afetar os resultados
3. **Docker**: Overhead do Docker pode impactar as métricas
4. **Warm-up**: O JVM pode precisar de mais tempo para warm-up em ambientes limitados

## Próximos Passos

1. Executar múltiplas iterações e calcular médias
2. Testar com diferentes cargas de trabalho
3. Monitorar uso de recursos durante os testes
4. Integrar com CI/CD para benchmarks automáticos
5. Adicionar gráficos de comparação visual

