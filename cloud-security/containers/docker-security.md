# Docker Security Scanning Tools

Container security assessment and vulnerability scanning tools.

## Docker Bench Security

```bash
# Clone and run
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

## Clair - Vulnerability Scanner

```bash
# Docker Compose setup
version: '3.1'
services:
  postgres:
    image: postgres:latest
    environment:
      POSTGRES_PASSWORD: password
  
  clair:
    image: quay.io/coreos/clair:latest
    depends_on:
      - postgres
```

## Trivy - Vulnerability Scanner

```bash
# Installation
sudo apt install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt update
sudo apt install trivy

# Scan container image
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL alpine:3.10

# Scan filesystem
trivy fs /path/to/project

# Scan Kubernetes cluster
trivy k8s --report summary cluster
```

## Anchore Engine

```bash
# Docker Compose deployment
curl https://engine.anchore.io/docs/quickstart/docker-compose.yaml > docker-compose.yaml
docker-compose up -d

# Add image for analysis
anchore-cli image add nginx:latest

# Wait for analysis completion
anchore-cli image wait nginx:latest

# Get vulnerability report
anchore-cli image vuln nginx:latest os
```

## Container Runtime Security

### Falco - Runtime Security Monitoring

```bash
# Installation
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt update
sudo apt install falco

# Start monitoring
sudo falco
```

## Security Best Practices Checks

- Base image vulnerabilities
- Dockerfile security practices
- Runtime configuration assessment
- Network security analysis
- Secret management evaluation
