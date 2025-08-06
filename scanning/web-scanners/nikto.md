# Nikto - Web Server Scanner

Open-source web server scanner for identifying potential problems and security vulnerabilities.

## Installation

```bash
# Ubuntu/Debian
apt install nikto

# From source
git clone https://github.com/sullo/nikto.git
cd nikto/program
```

## Basic Usage

```bash
# Basic scan
nikto -h http://example.com

# HTTPS scanning
nikto -h https://example.com

# Scan with specific port
nikto -h example.com -p 8080

# Multiple targets
nikto -h target1.com,target2.com,target3.com
```

## Advanced Options

```bash
# Authentication
nikto -h http://example.com -id username:password

# Custom user agent
nikto -h http://example.com -useragent "Custom Agent"

# Proxy usage
nikto -h http://example.com -useproxy http://proxy:8080

# SSL options
nikto -h https://example.com -ssl -nossl
```

## Scan Tuning

```bash
# Specific tests
nikto -h http://example.com -Tuning 9

# Multiple tuning options
nikto -h http://example.com -Tuning 1,2,3

# Exclude tests
nikto -h http://example.com -Tuning x 6
```

## Tuning Categories

```bash
0: File upload
1: Interesting files/Potential leaks
2: Misconfiguration/Default files
3: Information disclosure
4: Injection (XSS/Script/HTML)
5: Remote file retrieval - Inside web root
6: Denial of service
7: Remote file retrieval - Server wide
8: Command execution - Remote shell
9: SQL injection
a: Authentication bypass
b: Software identification
c: Remote source inclusion
```

## Output Options

```bash
# HTML report
nikto -h http://example.com -Format htm -output report.html

# XML output
nikto -h http://example.com -Format xml -output results.xml

# CSV format
nikto -h http://example.com -Format csv -output data.csv

# Text file
nikto -h http://example.com -output results.txt
```

## Performance Settings

```bash
# Timeout adjustment
nikto -h http://example.com -timeout 5

# Maximum scan time
nikto -h http://example.com -maxtime 3600

# Display options
nikto -h http://example.com -Display V
```

## Database Updates

```bash
# Update plugin database
nikto -update

# Check version
nikto -Version
```
