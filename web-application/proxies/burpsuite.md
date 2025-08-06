# Burp Suite - Web Application Security Testing Platform

Comprehensive platform for web application security testing and analysis.

## Installation

### Community Edition (Free)
```bash
# Download from PortSwigger website
wget https://portswigger.net/burp/releases/download?product=community&version=latest&type=Linux

# Make executable and run
chmod +x burpsuite_community_linux_*.sh
./burpsuite_community_linux_*.sh
```

### Professional Edition
Commercial version with advanced features and automated scanning.

## Core Components

### Proxy
Intercept and modify HTTP/HTTPS traffic between browser and server.

```bash
# Default proxy settings
HTTP Proxy: 127.0.0.1:8080
HTTPS Proxy: 127.0.0.1:8080

# Configure browser proxy settings
# Install Burp CA certificate for HTTPS interception
```

### Target
Organize and analyze application structure.
- Site map generation
- Scope definition
- Target analysis tools

### Spider
Automated crawling of web applications.
- Link discovery
- Form identification
- Content enumeration
- Custom crawling rules

### Scanner (Pro Only)
Automated vulnerability detection including:
- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Authentication flaws

## Manual Testing Tools

### Repeater
Manually modify and reissue individual requests.
- Request modification
- Response analysis
- Parameter manipulation
- Authentication testing

### Intruder
Automated attack tool for:
- Password brute forcing
- Fuzzing parameters
- Payload positioning
- Custom attack types

### Decoder
Encode/decode data in various formats:
- Base64 encoding
- URL encoding
- HTML encoding
- Hex encoding

### Comparer
Compare responses to identify differences:
- Word-level comparison
- Byte-level analysis
- Response highlighting

## Extensions

### BApp Store
Official extension marketplace with tools for:
- Additional scanners
- Specialized testing tools
- Integration plugins
- Custom functionality

### Popular Extensions
- Autorize (authorization testing)
- Param Miner (parameter discovery)
- Logger++ (advanced logging)
- JSON Beautifier

## Collaboration Features

- Project files for saving work
- Session sharing capabilities
- Report generation
- Finding annotation
