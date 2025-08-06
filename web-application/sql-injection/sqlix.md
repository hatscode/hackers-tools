# SQLiX - Blind SQL Injection Scanner

Fast blind SQL injection scanner with support for multiple injection techniques.

## Installation

```bash
# Download from GitHub
wget https://raw.githubusercontent.com/nullsecuritynet/tools/master/scanner/sqlix/release/sqlix.py
chmod +x sqlix.py

# Install dependencies
pip install requests
```

## Basic Usage

```bash
# Single URL testing
python3 sqlix.py -u "http://example.com/page?id=1"

# POST parameter testing  
python3 sqlix.py -u "http://example.com/login" -p "username=admin&password=test"

# Custom injection parameter
python3 sqlix.py -u "http://example.com/search" -g "query"
```

## Injection Techniques

```bash
# Boolean-based blind injection
python3 sqlix.py -u "http://example.com/page?id=1" -t boolean

# Time-based blind injection
python3 sqlix.py -u "http://example.com/page?id=1" -t time

# Error-based injection
python3 sqlix.py -u "http://example.com/page?id=1" -t error

# All techniques
python3 sqlix.py -u "http://example.com/page?id=1" -t all
```

## Advanced Options

```bash
# Custom payloads
python3 sqlix.py -u "http://example.com/page?id=1" --payloads custom_payloads.txt

# Proxy support
python3 sqlix.py -u "http://example.com/page?id=1" --proxy http://127.0.0.1:8080

# Custom headers
python3 sqlix.py -u "http://example.com/page?id=1" --header "X-Forwarded-For: 127.0.0.1"

# Request delay
python3 sqlix.py -u "http://example.com/page?id=1" --delay 2
```

## Database Detection

```bash
# Database fingerprinting
python3 sqlix.py -u "http://example.com/page?id=1" --dbms-detect

# Specific database testing
python3 sqlix.py -u "http://example.com/page?id=1" --dbms mysql
python3 sqlix.py -u "http://example.com/page?id=1" --dbms mssql
python3 sqlix.py -u "http://example.com/page?id=1" --dbms oracle
```

## Output Options

```bash
# Verbose output
python3 sqlix.py -u "http://example.com/page?id=1" -v

# Save results to file
python3 sqlix.py -u "http://example.com/page?id=1" -o results.txt

# JSON output format
python3 sqlix.py -u "http://example.com/page?id=1" --format json
```

## Performance Tuning

```bash
# Thread count
python3 sqlix.py -u "http://example.com/page?id=1" --threads 10

# Timeout configuration
python3 sqlix.py -u "http://example.com/page?id=1" --timeout 30

# Retry attempts
python3 sqlix.py -u "http://example.com/page?id=1" --retries 3
```

## Detection Features

- Automatic injection point detection
- Response analysis and comparison
- False positive filtering
- WAF detection capabilities

Lightweight alternative to SQLMap for quick blind SQL injection testing.
