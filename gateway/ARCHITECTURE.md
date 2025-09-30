# Arquitetura do Gateway

## Visão Geral

Este projeto implementa um gateway de microserviços seguindo os princípios de Clean Architecture, criando uma separação clara entre as responsabilidades e garantindo alta testabilidade e manutenibilidade.

## Estrutura de Camadas

### 1. Domain Layer (Camada de Domínio)
**Localização**: `src/main/java/com/example/gateway/domain/`

**Responsabilidades**:
- Contém as regras de negócio centrais
- Define as entidades e value objects
- Independente de frameworks externos

**Componentes**:
- `ServiceType`: Enum que define os tipos de serviços
- `RouteConfiguration`: Value Object para configuração de rotas
- `FallbackResponse`: Value Object para respostas de fallback

### 2. Application Layer (Camada de Aplicação)
**Localização**: `src/main/java/com/example/gateway/application/`

**Responsabilidades**:
- Orquestra os casos de uso
- Define interfaces (ports) para comunicação
- Implementa a lógica de aplicação

**Componentes**:
- **Ports** (Interfaces):
  - `RouteConfigurationPort`: Interface para configuração de rotas
  - `FallbackServicePort`: Interface para serviços de fallback
- **Services** (Casos de Uso):
  - `RouteConfigurationService`: Gerencia configurações de rotas
  - `FallbackService`: Gerencia respostas de fallback

### 3. Infrastructure Layer (Camada de Infraestrutura)
**Localização**: `src/main/java/com/example/gateway/infrastructure/`

**Responsabilidades**:
- Implementa adaptadores para frameworks externos
- Gerencia configurações
- Conecta com sistemas externos

**Componentes**:
- **Config**:
  - `GatewayProperties`: Configurações do gateway
  - `CircuitBreakerProperties`: Configurações do circuit breaker
- **Adapter**:
  - `SpringCloudGatewayAdapter`: Adaptador para Spring Cloud Gateway

### 4. Interface Layer (Camada de Interface)
**Localização**: `src/main/java/com/example/gateway/interfaces/`

**Responsabilidades**:
- Expõe APIs REST
- Trata requisições HTTP
- Valida entrada de dados

**Componentes**:
- `FallbackController`: Endpoints de fallback
- `GatewayInfoController`: Endpoints de informação do gateway
- `GlobalExceptionHandler`: Tratamento centralizado de exceções

## Fluxo de Dados

```
HTTP Request → Interface Layer → Application Layer → Domain Layer
                     ↓
Infrastructure Layer ← Application Layer ← Domain Layer
```

## Princípios Aplicados

### Clean Architecture
- **Independência de Frameworks**: O domínio não depende do Spring
- **Testabilidade**: Cada camada pode ser testada independentemente
- **Independência de UI**: A lógica de negócio não depende da interface
- **Independência de Banco**: Não há persistência, mas o princípio se aplica
- **Independência de Agentes Externos**: O domínio não conhece detalhes externos

### SOLID Principles
- **S** - Single Responsibility: Cada classe tem uma única responsabilidade
- **O** - Open/Closed: Extensível via interfaces, fechado para modificação
- **L** - Liskov Substitution: Implementações substituíveis
- **I** - Interface Segregation: Interfaces específicas e coesas
- **D** - Dependency Inversion: Dependências de abstrações

### Clean Code
- **Nomes Descritivos**: Classes e métodos com nomes claros
- **Funções Pequenas**: Métodos com responsabilidade única
- **Código Autoexplicativo**: Sem comentários desnecessários
- **Tratamento de Erros**: Exceções centralizadas
- **Testabilidade**: Código facilmente testável

## Benefícios da Arquitetura

1. **Manutenibilidade**: Mudanças em uma camada não afetam outras
2. **Testabilidade**: Cada componente pode ser testado isoladamente
3. **Flexibilidade**: Fácil troca de implementações via interfaces
4. **Escalabilidade**: Estrutura preparada para crescimento
5. **Legibilidade**: Código organizado e fácil de entender

## Configuração

### Desenvolvimento Local
```yaml
gateway:
  services:
    USER_SERVICE:
      url: http://localhost:8080
    PRODUCT_SERVICE:
      url: http://localhost:8081
    ORDER_SERVICE:
      url: http://localhost:8082
```

### Ambiente Docker
```yaml
gateway:
  services:
    USER_SERVICE:
      url: http://user-service:8080
    PRODUCT_SERVICE:
      url: http://product-service:8081
    ORDER_SERVICE:
      url: http://order-service:8082
```

## Testes

### Estrutura de Testes
- **Testes Unitários**: Testam componentes isoladamente
- **Testes de Integração**: Testam interação entre camadas
- **Testes de Contrato**: Validam interfaces

### Cobertura
- Domain Layer: 100% cobertura
- Application Layer: 100% cobertura
- Infrastructure Layer: Testes de integração
- Interface Layer: Testes de contrato
