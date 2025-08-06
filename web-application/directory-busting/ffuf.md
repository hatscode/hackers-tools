# Ffuf - Fast Web Fuzzer

High-performance web fuzzer written in Go with advanced filtering capabilities.

## Installation

```bash
# Go installation
go install github.com/ffuf/ffuf/v2@latest

# Download binary
wget https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_linux_amd64.tar.gz
tar -xzf ffuf_2.0.0_linux_amd64.tar.gz
```

## Directory Fuzzing

```bash
# Basic directory fuzzing
ffuf -u http://example.com/FUZZ -w wordlist.txt

# Multiple extensions
ffuf -u http://example.com/FUZZ -w wordlist.txt -e .php,.html,.js

# Recursive fuzzing
ffuf -u http://example.com/FUZZ -w wordlist.txt -recursion

# Custom depth
ffuf -u http://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3
```

## Parameter Fuzzing

```bash
# GET parameters
ffuf -u "http://example.com/page?FUZZ=test" -w params.txt

# POST data fuzzing
ffuf -u http://example.com/login -w passwords.txt -X POST -d "username=admin&password=FUZZ"

# Header fuzzing
ffuf -u http://example.com -w headers.txt -H "FUZZ: value"
```

## Advanced Filtering

```bash
# Filter by status code
ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404

# Filter by response size
ffuf -u http://example.com/FUZZ -w wordlist.txt -fs 1234

# Filter by word count
ffuf -u http://example.com/FUZZ -w wordlist.txt -fw 100

# Multiple filters
ffuf -u http://example.com/FUZZ -w wordlist.txt -fc 404,403 -fs 0
```

## Output Options

```bash
# Silent mode
ffuf -u http://example.com/FUZZ -w wordlist.txt -s

# Colored output
ffuf -u http://example.com/FUZZ -w wordlist.txt -c

# JSON output
ffuf -u http://example.com/FUZZ -w wordlist.txt -o results.json -of json

# HTML report
ffuf -u http://example.com/FUZZ -w wordlist.txt -o report.html -of html
```

## Performance Tuning

```bash
# Threading
ffuf -u http://example.com/FUZZ -w wordlist.txt -t 100

# Rate limiting
ffuf -u http://example.com/FUZZ -w wordlist.txt -rate 50

# Timeout
ffuf -u http://example.com/FUZZ -w wordlist.txt -timeout 5
```
