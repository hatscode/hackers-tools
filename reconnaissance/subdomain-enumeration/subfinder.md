# Subfinder - Fast Subdomain Discovery

High-performance subdomain discovery tool that uses passive sources.

## Installation

```bash
# Go installation  
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Download binary
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
```

## Basic Usage

```bash
# Single domain
subfinder -d example.com

# Multiple domains from file
subfinder -dL domains.txt

# Exclude wildcards
subfinder -d example.com -nW

# Silent mode
subfinder -d example.com -silent
```

## Output Options

```bash
# Save to file
subfinder -d example.com -o subdomains.txt

# JSON output
subfinder -d example.com -oJ -o results.json

# Only show resolved domains
subfinder -d example.com -nW -silent | httpx -silent
```

## API Configuration

```bash
# Create config directory
mkdir -p $HOME/.config/subfinder

# Add API keys to provider-config.yaml
virustotal: [API_KEY]
passivetotal: [API_KEY]
securitytrails: [API_KEY]
shodan: [API_KEY]
```

## Rate Limiting

```bash
# Custom rate limit
subfinder -d example.com -rl 10

# Threading control  
subfinder -d example.com -t 50
```

## Source Management

```bash
# List all sources
subfinder -ls

# Exclude specific sources
subfinder -d example.com -es virustotal,crtsh

# Use only specific sources
subfinder -d example.com -sources crtsh,certspotter
```
