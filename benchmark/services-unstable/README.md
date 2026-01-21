# Serviços Instáveis para Benchmark

Esta pasta contém serviços backend simulados que apresentam latência aleatória para testar a resiliência dos gateways.

## Estrutura

Cada serviço (api1, api2, api3) contém:
- **server.js**: Servidor Node.js/Express que simula latência aleatória (100ms a 1s)
- **package.json**: Dependências do Node.js
- **nginx.conf**: Configuração do Nginx como proxy reverso
- **Dockerfile**: Imagem Docker que executa Node.js + Nginx

## Comportamento

Cada requisição aos serviços terá uma latência aleatória entre **100ms e 1000ms**, simulando serviços instáveis ou com problemas de performance.

## Endpoints

### User Service (api1) - Porta 8080
- `GET /` - Health check
- `GET /users` - Lista de usuários
- `GET /users/:id` - Usuário específico
- `POST /users` - Criar usuário

### Product Service (api2) - Porta 8081
- `GET /` - Health check
- `GET /products` - Lista de produtos
- `GET /products/:id` - Produto específico
- `POST /products` - Criar produto

### Order Service (api3) - Porta 8082
- `GET /` - Health check
- `GET /orders` - Lista de pedidos
- `GET /orders/:id` - Pedido específico
- `POST /orders` - Criar pedido

## Uso

Os serviços são automaticamente usados pelos docker-compose do benchmark:
- `docker-compose.gateway.yml`
- `docker-compose.gateway-native.yml`
- `docker-compose.gateway-tomcat.yml`

## Teste Manual

Para testar um serviço manualmente:

```bash
cd benchmark/services-unstable/api1
docker build -t user-service-unstable .
docker run -p 8080:8080 user-service-unstable

# Em outro terminal
curl http://localhost:8080/users
```

