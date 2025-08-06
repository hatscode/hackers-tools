# NoSQLMap - NoSQL Database Injection Testing Tool

Automated NoSQL database injection testing tool for MongoDB, CouchDB, and other NoSQL systems.

## Installation

```bash
# Clone repository
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap

# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

```bash
# MongoDB injection testing
python3 nosqlmap.py -u "http://example.com/login" --post="username=admin&password=test"

# GET parameter testing
python3 nosqlmap.py -u "http://example.com/search?query=test"

# Custom headers
python3 nosqlmap.py -u "http://example.com/api" --header="Content-Type: application/json"
```

## Attack Techniques

```bash
# Authentication bypass
python3 nosqlmap.py -u "http://example.com/login" --post="username=admin&password=test" --attack-type=auth-bypass

# Data extraction
python3 nosqlmap.py -u "http://example.com/api/users" --attack-type=extract-data

# Blind injection
python3 nosqlmap.py -u "http://example.com/search" --attack-type=blind-injection
```

## Database Support

### MongoDB
- Authentication bypass
- Data extraction
- Schema enumeration
- JavaScript injection

### CouchDB
- View manipulation
- Document access
- Admin interface testing

### Redis
- Command injection
- Data dump attacks
- Configuration access

## Payload Customization

```bash
# Custom payload file
python3 nosqlmap.py -u "http://example.com/api" --payloads=custom_payloads.txt

# Specific injection points
python3 nosqlmap.py -u "http://example.com/search" --inject-at=query

# Encoding options
python3 nosqlmap.py -u "http://example.com/api" --encode=url
```

## Advanced Features

```bash
# Proxy support
python3 nosqlmap.py -u "http://example.com/api" --proxy=http://127.0.0.1:8080

# Custom user agent
python3 nosqlmap.py -u "http://example.com/api" --user-agent="Custom-Agent/1.0"

# Request delay
python3 nosqlmap.py -u "http://example.com/api" --delay=2

# Verbose output
python3 nosqlmap.py -u "http://example.com/api" --verbose
```

## Detection Methods

- Boolean-based blind injection
- Time-based blind injection
- Error-based injection
- Union-based injection
- JavaScript injection

Works well alongside traditional SQL injection tools for comprehensive database testing.
