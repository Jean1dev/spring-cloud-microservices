#!/bin/bash

echo "Configurando DNS no Docker daemon..."
echo ""

if [ ! -d "/etc/docker" ]; then
  echo "Criando diretório /etc/docker..."
  sudo mkdir -p /etc/docker
fi

echo "Criando arquivo daemon.json com configuração DNS..."
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
EOF

echo ""
echo "✅ Arquivo /etc/docker/daemon.json criado com sucesso!"
echo ""
echo "Reiniciando Docker daemon..."
sudo systemctl restart docker

echo ""
echo "✅ Docker reiniciado!"
echo ""
echo "Aguarde alguns segundos e teste:"
echo "  docker run --rm alpine nslookup services.gradle.org"
echo ""
echo "Ou execute o build:"
echo "  docker build -t gatewayjavanative:latest ."

