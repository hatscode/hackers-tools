# Dirb - Web Content Scanner

Classic web content scanner that searches for existing and hidden directories.

## Installation

```bash
# Ubuntu/Debian
apt-get install dirb

# From source
git clone https://github.com/v0re/dirb.git
cd dirb
./configure
make
sudo make install
```

## Basic Usage

```bash
# Default wordlist scan
dirb http://example.com

# Custom wordlist  
dirb http://example.com /path/to/wordlist.txt

# Specific extensions
dirb http://example.com wordlist.txt -X .php,.html,.js

# Case insensitive
dirb http://example.com -i
```

## Advanced Options

```bash
# Authentication
dirb http://example.com -u username:password

# Custom user agent
dirb http://example.com -a "Mozilla/5.0..."

# Cookies
dirb http://example.com -c "sessionid=abc123"

# Custom headers
dirb http://example.com -H "X-Forwarded-For: 127.0.0.1"
```

## Filtering Options

```bash
# Hide specific status codes
dirb http://example.com -N 404

# Show only specific codes
dirb http://example.com -w

# Fine tuning
dirb http://example.com -f

# Silent mode
dirb http://example.com -S
```

## Output Options

```bash
# Save results
dirb http://example.com -o results.txt

# Different output formats
dirb http://example.com -o results.txt -p

# Print location header
dirb http://example.com -l
```

## Built-in Wordlists

Common wordlists included:
- common.txt - Basic directories
- big.txt - Comprehensive list
- small.txt - Quick scan
- vulns/ - Vulnerability-specific paths

## Performance

```bash
# Delay between requests
dirb http://example.com -z 1000

# Don't search recursively
dirb http://example.com -r
```
