# Findomain - Fast Cross-Platform Subdomain Enumerator

Multi-threaded subdomain finder written in Rust with monitoring capabilities.

## Installation

```bash
# Download latest release
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux

# Using cargo
cargo install findomain

# Arch Linux
yay -S findomain
```

## Basic Usage

```bash
# Single target
findomain -t example.com

# Multiple targets
findomain -f domains.txt

# Quiet output
findomain -t example.com -q

# Unique results only
findomain -t example.com -u
```

## Output Options

```bash
# Save to file
findomain -t example.com -o csv

# Different formats
findomain -t example.com -o json
findomain -t example.com -o txt

# Custom filename
findomain -t example.com --output-name custom_scan
```

## Monitoring Mode

```bash
# Monitor for new subdomains
findomain -t example.com -m

# Monitoring with notifications
findomain -t example.com -m --notify

# Custom monitoring interval
findomain -t example.com -m --monitoring-interval 3600
```

## API Configuration

```bash
# Set environment variables
export findomain_virustotal_token="YOUR_TOKEN"
export findomain_securitytrails_token="YOUR_TOKEN"
export findomain_spyse_token="YOUR_TOKEN"
```

## Performance Tuning

Multi-threaded by default with automatic optimization based on system resources.

## Integration

```bash
# Chain with httpx
findomain -t example.com -q | httpx -silent -title
```
