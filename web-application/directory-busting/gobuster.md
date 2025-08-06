# Gobuster - Directory and File Brute Forcer

Fast directory and file enumeration tool written in Go.

## Installation

```bash
# Go installation
go install github.com/OJ/gobuster/v3@latest

# Ubuntu/Debian
apt install gobuster

# Download binary
wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz
```

## Directory Enumeration

```bash
# Basic directory scan
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt

# Custom wordlist
gobuster dir -u http://example.com -w custom_wordlist.txt

# Multiple extensions
gobuster dir -u http://example.com -w wordlist.txt -x php,html,js,txt

# Custom status codes
gobuster dir -u http://example.com -w wordlist.txt -s 200,204,301,302,307
```

## DNS Enumeration

```bash
# Subdomain enumeration
gobuster dns -d example.com -w subdomains.txt

# Wildcard detection
gobuster dns -d example.com -w subdomains.txt -i

# Custom resolvers
gobuster dns -d example.com -w subdomains.txt -r 8.8.8.8,1.1.1.1
```

## S3 Bucket Enumeration

```bash
# Find S3 buckets
gobuster s3 -w bucket_names.txt

# Specific region
gobuster s3 -w bucket_names.txt -r us-west-2
```

## Advanced Options

```bash
# Threading
gobuster dir -u http://example.com -w wordlist.txt -t 50

# Timeout settings
gobuster dir -u http://example.com -w wordlist.txt --timeout 10s

# User agent
gobuster dir -u http://example.com -w wordlist.txt -a "Custom-Agent/1.0"

# Cookies
gobuster dir -u http://example.com -w wordlist.txt -c "session=abc123"
```

## Output Options

```bash
# Verbose output
gobuster dir -u http://example.com -w wordlist.txt -v

# Output to file
gobuster dir -u http://example.com -w wordlist.txt -o results.txt

# JSON output
gobuster dir -u http://example.com -w wordlist.txt -o results.json --json
```
