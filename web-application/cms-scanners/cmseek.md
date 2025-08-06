# CMSeeK - Content Management System Detection

Automated CMS detection and enumeration tool supporting multiple platforms.

## Installation

```bash
# Clone repository
git clone https://github.com/Tuhinshubhra/CMSeeK.git
cd CMSeeK

# Install dependencies
pip3 install -r requirements.txt
```

## Basic Usage

```bash
# Single target scan
python3 cmseek.py -u http://example.com

# List mode from file
python3 cmseek.py -l targets.txt

# Follow redirects
python3 cmseek.py -u http://example.com --follow-redirect

# Random user agent
python3 cmseek.py -u http://example.com --random-agent
```

## Advanced Options

```bash
# Brute force mode
python3 cmseek.py -u http://example.com --bruteforce

# Deep scan
python3 cmseek.py -u http://example.com --deep

# Skip detection
python3 cmseek.py -u http://example.com --skip-detection

# Force CMS type
python3 cmseek.py -u http://example.com --cms wordpress
```

## Supported CMS Platforms

### Popular Systems
- WordPress
- Joomla  
- Drupal
- Magento
- PrestaShop
- OpenCart
- TYPO3

### Specialized Platforms
- Ghost
- Craft CMS
- ProcessWire
- Concrete5
- SilverStripe
- ModX
- Umbraco

## Detection Methods

### Fingerprinting Techniques
- HTTP header analysis
- Meta tag inspection
- JavaScript library detection
- CSS framework identification
- Directory structure analysis

### Version Detection
- Change log analysis
- README file inspection
- Version-specific signatures
- Update mechanism fingerprinting

## Enumeration Features

### User Enumeration
- Author discovery
- Admin user identification
- User ID enumeration
- Login attempt analysis

### Plugin/Module Discovery
- Active component detection
- Popular plugin enumeration
- Vulnerable component identification

### Theme Detection
- Active theme identification
- Theme version detection
- Custom theme analysis

## Vulnerability Assessment

### Known Vulnerabilities
- CVE database matching
- Public exploit availability
- Security advisory correlation

### Common Issues
- Default credential testing
- Weak configuration detection
- Exposed administrative interfaces

## Output Options

```bash
# Save results
python3 cmseek.py -u http://example.com --save-results

# Custom output directory
python3 cmseek.py -u http://example.com --output-dir /tmp/cmseek

# JSON output
python3 cmseek.py -u http://example.com --json-output
```

## Performance Tuning

```bash
# Thread count
python3 cmseek.py -u http://example.com --threads 5

# Request delay
python3 cmseek.py -u http://example.com --delay 2

# Timeout configuration
python3 cmseek.py -u http://example.com --timeout 30
```

Versatile CMS detection tool with broad platform coverage and detailed enumeration capabilities.
