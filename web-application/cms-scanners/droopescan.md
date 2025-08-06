# Droopescan - Drupal and SilverStripe Scanner

Security scanner for Drupal, SilverStripe, and WordPress content management systems.

## Installation

```bash
# Python pip installation
pip install droopescan

# From source
git clone https://github.com/droope/droopescan.git
cd droopescan
python setup.py install
```

## Drupal Scanning

```bash
# Basic Drupal scan
droopescan scan drupal -u http://example.com

# Enumerate plugins
droopescan scan drupal -u http://example.com --enumerate p

# Enumerate themes
droopescan scan drupal -u http://example.com --enumerate t

# Enumerate version
droopescan scan drupal -u http://example.com --enumerate v

# All enumeration
droopescan scan drupal -u http://example.com --enumerate p,t,v,i
```

## SilverStripe Scanning

```bash
# Basic SilverStripe scan
droopescan scan silverstripe -u http://example.com

# Version enumeration
droopescan scan silverstripe -u http://example.com --enumerate v

# Module enumeration
droopescan scan silverstripe -u http://example.com --enumerate m
```

## WordPress Scanning

```bash
# WordPress compatibility mode
droopescan scan wordpress -u http://example.com

# Plugin enumeration
droopescan scan wordpress -u http://example.com --enumerate p

# Theme enumeration  
droopescan scan wordpress -u http://example.com --enumerate t
```

## Advanced Options

```bash
# Custom threads
droopescan scan drupal -u http://example.com --threads 10

# Custom timeout
droopescan scan drupal -u http://example.com --timeout 30

# Proxy support
droopescan scan drupal -u http://example.com --proxy http://127.0.0.1:8080

# Custom user agent
droopescan scan drupal -u http://example.com --user-agent "Custom-Scanner/1.0"
```

## Output Options

```bash
# JSON output
droopescan scan drupal -u http://example.com --output json

# Standard output format
droopescan scan drupal -u http://example.com --output standard

# Save to file
droopescan scan drupal -u http://example.com > results.txt
```

## Statistics and Information

```bash
# Show statistics
droopescan stats

# List supported CMS
droopescan --help

# Version information
droopescan --version
```

## Enumeration Categories

### Plugins/Modules (`p`,`m`)
- Popular plugin detection
- Version identification
- Security advisory matching

### Themes (`t`)
- Active theme identification
- Theme version detection
- Known vulnerability checking

### Version (`v`)
- CMS version fingerprinting
- Build number identification
- Security update status

### Interesting URLs (`i`)
- Admin interface discovery
- Configuration file exposure
- Backup file detection

## Vulnerability Database

- CVE cross-referencing
- Security advisory integration
- Known exploit identification
- Patch availability status

Lightweight alternative to CMS-specific scanners with multi-platform support.
