# Wfuzz - Web Application Fuzzer

Flexible web application fuzzer designed for brute forcing web applications.

## Installation

```bash
# Using pip
pip install wfuzz

# Ubuntu/Debian
apt-get install wfuzz

# From source
git clone https://github.com/xmendez/wfuzz.git
cd wfuzz
python setup.py install
```

## Basic Usage

```bash
# Directory fuzzing
wfuzz -c -w wordlist.txt http://example.com/FUZZ

# Parameter fuzzing
wfuzz -c -w wordlist.txt "http://example.com/page?param=FUZZ"

# POST data fuzzing
wfuzz -c -w passwords.txt -d "user=admin&pass=FUZZ" http://example.com/login

# Multiple injection points
wfuzz -c -w users.txt -w passwords.txt -d "user=FUZZ&pass=FUZ2Z" http://example.com/login
```

## Advanced Filtering

```bash
# Hide by status code
wfuzz -c --hc 404 -w wordlist.txt http://example.com/FUZZ

# Hide by response length
wfuzz -c --hl 20 -w wordlist.txt http://example.com/FUZZ

# Show only specific codes
wfuzz -c --sc 200,301 -w wordlist.txt http://example.com/FUZZ

# Complex filtering
wfuzz -c --hc 404 --hw 0 -w wordlist.txt http://example.com/FUZZ
```

## Headers and Cookies

```bash
# Custom headers
wfuzz -c -H "X-Forwarded-For: FUZZ" -w ips.txt http://example.com

# Cookie fuzzing
wfuzz -c -b "sessionid=FUZZ" -w cookies.txt http://example.com

# User agent fuzzing
wfuzz -c -H "User-Agent: FUZZ" -w user-agents.txt http://example.com
```

## Payloads and Encoders

```bash
# Range payload
wfuzz -c -z range,1-100 http://example.com/page?id=FUZZ

# File payload
wfuzz -c -z file,wordlist.txt http://example.com/FUZZ

# Base64 encoding
wfuzz -c -w wordlist.txt -e base64 http://example.com/page?data=FUZZ

# URL encoding
wfuzz -c -w wordlist.txt -e urlencode http://example.com/page?param=FUZZ
```

## Output Options

```bash
# Save to file
wfuzz -c -w wordlist.txt -f results.txt http://example.com/FUZZ

# JSON output
wfuzz -c -w wordlist.txt -o json http://example.com/FUZZ

# HTML output
wfuzz -c -w wordlist.txt -o html http://example.com/FUZZ
```

## Performance Tuning

```bash
# Threading
wfuzz -c -t 50 -w wordlist.txt http://example.com/FUZZ

# Connection delay
wfuzz -c -s 2 -w wordlist.txt http://example.com/FUZZ
```
