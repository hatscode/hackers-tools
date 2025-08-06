# Amass - Attack Surface Discovery

Comprehensive subdomain enumeration tool maintained by the OWASP Foundation.

## Installation

```bash
# Go installation
go install -v github.com/OWASP/Amass/v3/...@master

# Snap package
snap install amass

# Docker
docker pull caffix/amass
```

## Passive Enumeration

```bash
# Basic passive scan
amass enum -passive -d example.com

# Multiple domains
amass enum -passive -df domains.txt

# Specific data sources
amass enum -passive -src crtsh,threatcrowd -d example.com

# Output to file
amass enum -passive -d example.com -o passive_results.txt
```

## Active Enumeration

```bash
# Active scanning with DNS resolution
amass enum -active -d example.com

# Brute force mode
amass enum -brute -d example.com

# Custom wordlist
amass enum -brute -w custom_wordlist.txt -d example.com

# Rate limiting
amass enum -active -d example.com -rf 10
```

## Configuration

```yaml
# config.yaml example
scope:
  domains:
    - example.com
  blacklisted:
    - dev.example.com
    
data_sources:
  crtsh:
    ttl: 4320
  virustotal:
    apikey: YOUR_API_KEY
```

## Visualization

```bash
# Generate graph data
amass viz -maltego amass_output.json

# Neo4j import
amass viz -neo4j neo4j://localhost:7687 -d amass.db
```

## Integration

Works well with other tools like Nmap and Nuclei for follow-up scanning.
