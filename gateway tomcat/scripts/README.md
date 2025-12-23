# Scripts do Gateway Spring Cloud

Este diretório contém todos os scripts organizados por funcionalidade para facilitar o desenvolvimento, teste e deployment do Gateway Spring Cloud.

## 📁 Estrutura de Diretórios

```
scripts/
├── auth/           # Scripts de autenticação e tokens
├── test-api/       # Scripts de teste de APIs
├── utils/          # Scripts de utilidade
├── deployment/     # Scripts de deployment
└── run.sh          # Script principal para executar outros scripts
```

## 🚀 Como Usar

### Script Principal (Recomendado)
```bash
# Ver ajuda completa
./scripts/run.sh help

# Obter token do Keycloak
./scripts/run.sh auth token

# Testar gateway
./scripts/run.sh test-api gateway

# Verificar serviços
./scripts/run.sh utils check
```

### Execução Direta
```bash
# Autenticação
./scripts/auth/get-keycloak-token.sh
./scripts/auth/quick-token.sh

# Testes
./scripts/test-api/test-gateway-with-token.sh
./scripts/test-api/test-services.sh
./scripts/test-api/test-circuit-breaker.sh

# Utilitários
./scripts/utils/check-services.sh
./scripts/utils/clean-logs.sh

# Deployment
./scripts/deployment/start-all.sh
./scripts/deployment/stop-all.sh
```

## 📋 Scripts por Categoria

### 🔐 **auth/** - Autenticação
- **`get-keycloak-token.sh`**: Script completo para obter token do Keycloak
  - Verificação de dependências
  - Tratamento de erros
  - Opções para salvar e decodificar token
- **`quick-token.sh`**: Script rápido para obter token

### 🧪 **test-api/** - Testes de API
- **`test-gateway-with-token.sh`**: Testa o gateway com autenticação
- **`test-services.sh`**: Testa os serviços individuais
- **`test-circuit-breaker.sh`**: Testa o funcionamento do circuit breaker
- **`demo.sh`**: Demonstração completa de todos os testes
- **`test-gateway.sh`**: Teste completo do gateway (com jq)
- **`test-gateway-simple.sh`**: Teste simples do gateway (sem jq)
- **`test-api.sh`**: Teste de APIs específicas
- **`run-performance-tests.sh`**: Testes de performance com Gatling

### 🛠️ **utils/** - Utilitários
- **`check-services.sh`**: Verifica o status de todos os serviços
- **`clean-logs.sh`**: Limpa logs, build e containers Docker

### 🚀 **deployment/** - Deployment
- **`start-all.sh`**: Inicia todos os serviços (Docker + Gateway)
- **`stop-all.sh`**: Para todos os serviços

## 🔧 Configurações

Todos os scripts usam as configurações do `application.yml`:
- **Keycloak**: `http://localhost:8084`
- **Gateway**: `http://localhost:8083`
- **User Service**: `http://localhost:8080`
- **Product Service**: `http://localhost:8081`
- **Order Service**: `http://localhost:8082`

## 📝 Exemplos de Uso

### Fluxo Completo de Desenvolvimento
```bash
# 1. Iniciar todos os serviços
./scripts/run.sh deploy start

# 2. Verificar se tudo está rodando
./scripts/run.sh utils check

# 3. Obter token para testes
./scripts/run.sh auth quick-token

# 4. Testar gateway
./scripts/run.sh test-api gateway

# 5. Parar todos os serviços
./scripts/run.sh deploy stop
```

### Testes Rápidos
```bash
# Testar apenas autenticação
./scripts/run.sh auth token --decode

# Testar circuit breaker
./scripts/run.sh test-api circuit

# Executar demonstração completa
./scripts/run.sh test-api demo

# Teste simples (sem jq)
./scripts/run.sh test-api simple

# Testes de performance
./scripts/run.sh test-api performance

# Limpar logs
./scripts/run.sh utils clean logs
```

### Desenvolvimento
```bash
# Verificar status dos serviços
./scripts/run.sh utils check

# Limpar tudo e reiniciar
./scripts/run.sh utils clean all
./scripts/run.sh deploy start
```

## 🎯 Benefícios da Organização

- ✅ **Separação clara** de responsabilidades
- ✅ **Fácil manutenção** e localização de scripts
- ✅ **Reutilização** de código entre scripts
- ✅ **Documentação** centralizada
- ✅ **Execução simplificada** através do script principal
- ✅ **Padronização** de cores e mensagens
