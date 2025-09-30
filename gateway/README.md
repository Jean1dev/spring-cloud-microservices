# Spring Cloud Gateway - Microservices Gateway

Este projeto implementa um gateway simples usando Spring Cloud Gateway para rotear requisições para 3 microserviços: user-service, product-service e order-service.

## Estrutura Organizada

```
src/main/java/com/example/gateway/
├── GatewayApplication.java   # Aplicação principal que compõe as rotas
└── apis/                     # Configurações das APIs
    ├── BaseApiConfig.java    # Classe base com funcionalidades comuns
    ├── UserApiConfig.java    # Configuração da API de usuários
    ├── ProductApiConfig.java # Configuração da API de produtos
    └── OrderApiConfig.java   # Configuração da API de pedidos

src/main/resources/
├── application.yml          # Configuração principal
└── application-docker.yml   # Configuração para Docker
```

## Funcionalidades

- **Roteamento Simples**: Roteia requisições para os microserviços baseado no path
- **Circuit Breaker**: Implementa circuit breaker usando Resilience4J
- **Fallback**: Endpoints de fallback quando os serviços estão indisponíveis
- **Middleware de Logging**: Registra todas as requisições e respostas com detalhes de roteamento
- **Configuração Flexível**: Funciona em desenvolvimento e Docker
- **Código Limpo**: Implementação direta e fácil de entender

## Rotas Configuradas

### Rotas Diretas
- `GET /users/**` → user-service (porta 8080)
- `GET /products/**` → product-service (porta 8081)  
- `GET /orders/**` → order-service (porta 8082)

### Rotas com Prefixo
- `GET /user-service/**` → user-service (porta 8080)
- `GET /product-service/**` → product-service (porta 8081)
- `GET /order-service/**` → order-service (porta 8082)

## Endpoints de Fallback

- `GET /fallback/user` - Fallback para user-service
- `GET /fallback/product` - Fallback para product-service
- `GET /fallback/order` - Fallback para order-service

## Middleware de Logging

O gateway inclui um middleware de logging que registra todas as requisições e respostas:

### Logs de Requisição
```
🚀 [2024-01-15 10:30:45.123] INCOMING REQUEST: GET http://localhost:8083/users -> Target: user-service
📋 [2024-01-15 10:30:45.124] Headers - Host: localhost:8083, User-Agent: curl/7.68.0, X-Forwarded-For: null
🔍 [2024-01-15 10:30:45.125] Query Params: {page=[1], size=[10]}
```

### Logs de Resposta
```
✅ [2024-01-15 10:30:45.456] RESPONSE SENT: GET http://localhost:8083/users -> Status: 200 OK
```

### Configuração de Logging
```yaml
logging:
  level:
    com.example.gateway.filters: INFO
    org.springframework.cloud.gateway: DEBUG
    reactor.netty.http.client: DEBUG
```

## Como Executar

### Desenvolvimento Local

1. Inicie os microserviços:
```bash
docker-compose up user-service product-service order-service
```

2. Execute o gateway:
```bash
./gradlew bootRun
```

O gateway estará disponível em `http://localhost:8083`

### Docker Compose

Execute todos os serviços incluindo o gateway:
```bash
docker-compose up --build
```

## Exemplos de Uso

### Testando as APIs através do Gateway

```bash
# User Service
curl http://localhost:8083/users
curl http://localhost:8083/users/1
curl http://localhost:8083/user-service/users

# Product Service  
curl http://localhost:8083/products
curl http://localhost:8083/products/1
curl http://localhost:8083/product-service/products

# Order Service
curl http://localhost:8083/orders
curl http://localhost:8083/orders/1
curl http://localhost:8083/order-service/orders
```

### Endpoints de Monitoramento

```bash
# Health Check
curl http://localhost:8083/actuator/health

# Gateway Routes
curl http://localhost:8083/actuator/gateway/routes
```

## Configuração

### Circuit Breaker
- **Failure Rate Threshold**: 50%
- **Wait Duration**: 30 segundos
- **Sliding Window Size**: 10 chamadas
- **Minimum Number of Calls**: 5 chamadas

### Portas
- Gateway: 8083
- User Service: 8080
- Product Service: 8081
- Order Service: 8082

## Características da Implementação

### Organização
- **Separação de Responsabilidades**: Cada API tem sua própria configuração
- **Classe Base**: Funcionalidades comuns centralizadas
- **Composição**: GatewayApplication compõe todas as configurações

### Simplicidade
- **Código Limpo**: Estrutura organizada e fácil de entender
- **Fácil Manutenção**: Cada API pode ser modificada independentemente
- **Configuração Mínima**: Apenas o necessário para funcionar

### Flexibilidade
- **Desenvolvimento Local**: URLs localhost para desenvolvimento
- **Ambiente Docker**: URLs de containers para produção
- **Perfis Spring**: Detecção automática do ambiente

## Scripts de Teste

O projeto inclui scripts shell para facilitar os testes do gateway:

### test-gateway.sh
Script completo com formatação colorida e JSON formatado (requer jq):
```bash
./test-gateway.sh
```

### test-gateway-simple.sh
Script simples sem dependências externas:
```bash
./test-gateway-simple.sh
```

### test-api.sh
Script para testar APIs específicas:
```bash
./test-api.sh user list      # Lista de usuários
./test-api.sh product get    # Produto específico
./test-api.sh order fallback # Fallback de pedidos
```

### Teste Manual
```bash
curl http://localhost:8083/users
curl http://localhost:8083/products
curl http://localhost:8083/orders
```

## Tecnologias Utilizadas

- Spring Boot 3.5.6
- Spring Cloud Gateway
- Spring Cloud Circuit Breaker (Resilience4J)
- Java 21
- Gradle
- Docker
- JUnit 5
- AssertJ
- Reactor Test
