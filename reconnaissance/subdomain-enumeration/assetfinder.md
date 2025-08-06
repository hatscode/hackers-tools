# Assetfinder - Domain and Subdomain Discovery

Simple tool to find domains and subdomains related to a given domain.

## Installation

```bash
# Go installation
go install github.com/tomnomnom/assetfinder@latest

# Manual download
wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz
tar -xzf assetfinder-linux-amd64-0.1.1.tgz
```

## Basic Commands

```bash
# Find subdomains
assetfinder example.com

# Include related domains
assetfinder --subs-only example.com

# Find related domains
echo "example.com" | assetfinder

# Pipe to other tools
assetfinder example.com | grep admin
```

## Data Sources

Uses multiple sources including:
- Certificate Transparency logs
- DNS databases
- Web archives
- Search engines

## Output Processing

```bash
# Remove duplicates and sort
assetfinder example.com | sort -u

# Filter for specific patterns
assetfinder example.com | grep -E "(api|admin|dev)"

# Check for live domains
assetfinder example.com | httprobe

# Combine with other tools
assetfinder example.com | sort -u | httpx -title -tech-detect
```

## Limitations

- No API key configuration
- Limited source customization
- Passive enumeration only

## Integration

Often used as first step in reconnaissance chain, followed by more detailed enumeration tools.
