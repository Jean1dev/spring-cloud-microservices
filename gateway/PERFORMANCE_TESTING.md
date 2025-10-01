# Testes de Performance - Spring Cloud Gateway

Este projeto inclui testes de performance usando Gatling com Scala para validar o comportamento do Spring Cloud Gateway sob diferentes cenários de carga.

## Estrutura dos Testes

```
src/gatling/
└── scala/com/example/gateway/performance/
    ├── GatewayPerformanceTest.scala    # Teste básico de performance
    ├── HeavyLoadTest.scala             # Teste de carga pesada
    └── CircuitBreakerTest.scala        # Teste de Circuit Breaker
```

## Tipos de Testes

### 1. GatewayPerformanceTest
- **Objetivo**: Teste básico de performance do Gateway
- **Cenários**: Health check, operações CRUD nos serviços
- **Carga**: 10 usuários simultâneos, rampa até 50 usuários em 30s, 20 usuários/seg por 60s
- **Assertions**: 
  - Tempo de resposta máximo < 5s
  - Tempo de resposta médio < 2s
  - Taxa de sucesso > 80% (considera indisponibilidade de serviços backend)

### 2. HeavyLoadTest
- **Objetivo**: Teste de carga pesada e stress
- **Cenários**: Múltiplas requisições concorrentes, teste de Circuit Breaker
- **Carga**: 100 usuários simultâneos, 50 usuários/seg por 120s
- **Assertions**:
  - Tempo de resposta máximo < 10s
  - Tempo de resposta médio < 3s
  - Taxa de sucesso > 85%

### 3. CircuitBreakerTest
- **Objetivo**: Teste de resiliência e Circuit Breaker
- **Cenários**: Teste de fallback, stress para ativar Circuit Breaker
- **Carga**: 50 usuários simultâneos, requisições de alta frequência
- **Assertions**:
  - Tempo de resposta máximo < 8s
  - Tempo de resposta médio < 2.5s
  - Taxa de sucesso > 80%

## Como Executar os Testes

### Pré-requisitos
1. O Gateway deve estar rodando em `http://localhost:8083`
2. Os serviços backend devem estar disponíveis (ou simulados)

### Execução Individual
```bash
# Compilar os testes primeiro (opcional, o gatlingRun faz automaticamente)
./gradlew compileGatlingScala

# Teste básico
./gradlew gatlingRun --simulation=com.example.gateway.performance.GatewayPerformanceTest

# Teste de carga pesada
./gradlew gatlingRun --simulation=com.example.gateway.performance.HeavyLoadTest

# Teste de Circuit Breaker
./gradlew gatlingRun --simulation=com.example.gateway.performance.CircuitBreakerTest
```

### Execução com Script (Recomendado)
```bash
./run-performance-tests.sh
```

O script verifica automaticamente:
- Se o Java está instalado
- Se o Gateway está rodando
- Compila os testes antes de executar

**Nota**: Se você não tiver Java instalado, instale com:
```bash
sudo apt install openjdk-21-jdk
```

### Executar Todos os Testes
```bash
./gradlew gatlingRun
```

## Configurações

O Gatling usa configurações padrão otimizadas. A versão do plugin é especificada no `build.gradle`:

```gradle
plugins {
    id 'scala'
    id 'io.gatling.gradle' version '3.11.5'
}

dependencies {
    implementation 'org.scala-lang:scala-library:2.13.12'
}
```

**Nota**: Usamos Gatling 3.11.5 com plugin Scala para compatibilidade com Spring Boot 3.x e Netty 4.x.

## Relatórios

Os relatórios são gerados em `build/reports/gatling/` com os seguintes formatos:
- **HTML**: Relatório interativo com gráficos e métricas detalhadas
- **CSV**: Dados brutos para análise posterior
- **JSON**: Dados estruturados para integração com ferramentas de CI/CD

### Métricas Importantes
- **Response Time**: Tempo de resposta das requisições
- **Throughput**: Requisições por segundo
- **Error Rate**: Taxa de erro das requisições
- **Active Users**: Usuários ativos simultâneos
- **Circuit Breaker Status**: Estado dos circuit breakers

## Cenários de Teste

### Endpoints Testados
- `GET /actuator/health` - Health check
- `GET /user-service/users` - Listar usuários
- `POST /user-service/users` - Criar usuário
- `GET /product-service/products` - Listar produtos
- `POST /product-service/products` - Criar produto
- `GET /order-service/orders` - Listar pedidos
- `POST /order-service/orders` - Criar pedido

### Padrões de Carga
1. **Warm-up**: 5s de pausa inicial
2. **Ramp-up**: Aumento gradual de usuários
3. **Sustained Load**: Carga constante por período
4. **Peak Load**: Pico de carga para testar limites
5. **Cool-down**: Redução gradual

## Troubleshooting

### Problemas Comuns
1. **Gateway não responde**: Verifique se está rodando em localhost:8083
2. **Java não encontrado**: Instale com `sudo apt install openjdk-21-jdk`
3. **Task 'compileGatlingScala' not found**: Adicione o plugin `scala` ao build.gradle
4. **ClassNotFoundException**: Execute `./gradlew compileGatlingScala` para compilar os testes Scala
5. **NoClassDefFoundError: io.netty.channel.IoOps**: Problema de compatibilidade. Use Gatling 3.11.5 com Spring Boot 3.x
6. **Circuit Breaker ativado**: Comportamento esperado em carga alta

### Logs Importantes
- Gatling logs: Console durante execução
- Gateway logs: Verificar comportamento dos filtros e circuit breakers
- Performance logs: Métricas detalhadas nos relatórios

## Integração com CI/CD

Para integrar com pipelines de CI/CD:

```bash
# Executar teste específico e falhar build se assertions falharem
./gradlew gatlingRun --simulation=com.example.gateway.performance.GatewayPerformanceTest

# Ou executar todos os testes
./gradlew gatlingRun
```

O build falhará automaticamente se as assertions configuradas não forem atendidas.

## Próximos Passos

1. **Monitoramento**: Integrar com Prometheus/Grafana
2. **Baseline**: Estabelecer métricas de baseline
3. **Automação**: Executar testes automaticamente em PRs
4. **Alertas**: Configurar alertas baseados em degradação de performance
