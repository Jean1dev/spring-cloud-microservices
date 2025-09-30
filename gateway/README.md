# Spring Cloud Gateway - Microservices Gateway

Este projeto implementa um gateway usando Spring Cloud Gateway seguindo os princípios de **Clean Architecture** e **Clean Code** para rotear requisições para 3 microserviços: user-service, product-service e order-service.

## Arquitetura

O projeto segue os princípios de Clean Architecture com as seguintes camadas:

```
src/main/java/com/example/gateway/
├── domain/                    # Camada de Domínio
│   ├── model/                # Entidades e Value Objects
│   └── service/              # Serviços de domínio
├── application/              # Camada de Aplicação
│   ├── port/                 # Interfaces (Ports)
│   └── service/              # Casos de uso
├── infrastructure/           # Camada de Infraestrutura
│   ├── config/               # Configurações
│   └── adapter/              # Adaptadores externos
└── interfaces/               # Camada de Interface
    └── rest/                 # Controllers REST
```

## Funcionalidades

- **Roteamento**: Roteia requisições para os microserviços baseado no path
- **Circuit Breaker**: Implementa circuit breaker usando Resilience4J para resiliência
- **Fallback**: Endpoints de fallback quando os serviços estão indisponíveis
- **Clean Architecture**: Separação clara de responsabilidades
- **SOLID Principles**: Aplicação dos princípios SOLID
- **Testabilidade**: Cobertura de testes unitários
- **Configuração Externa**: Configurações flexíveis via properties
- **Tratamento de Exceções**: Handler centralizado para exceções

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

## Princípios de Clean Code e Clean Architecture Aplicados

### Clean Architecture
- **Separação de Camadas**: Domínio, Aplicação, Infraestrutura e Interface
- **Inversão de Dependência**: Uso de interfaces (ports) para desacoplamento
- **Independência de Frameworks**: Lógica de negócio isolada do Spring

### SOLID Principles
- **Single Responsibility**: Cada classe tem uma única responsabilidade
- **Open/Closed**: Extensível via interfaces, fechado para modificação
- **Liskov Substitution**: Implementações substituíveis via interfaces
- **Interface Segregation**: Interfaces específicas e coesas
- **Dependency Inversion**: Dependências de abstrações, não implementações

### Clean Code
- **Nomes Descritivos**: Classes e métodos com nomes claros
- **Funções Pequenas**: Métodos com responsabilidade única
- **Comentários Desnecessários**: Código autoexplicativo
- **Tratamento de Erros**: Exceções centralizadas e consistentes
- **Testabilidade**: Código facilmente testável

### Java 21 Features
- **Records**: Uso de Records para Value Objects imutáveis
- **Pattern Matching**: Switch expressions com Pattern Matching
- **Stream API**: Uso de streams e collectors modernos
- **Validation**: Validação integrada nos Records
- **Builder Pattern**: Mantido para compatibilidade e flexibilidade

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
