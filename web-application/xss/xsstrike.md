# XSStrike - Advanced XSS Detection Suite

Advanced Cross-Site Scripting detection and exploitation toolkit.

## Installation

```bash
# Clone repository
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike

# Install requirements
pip3 install -r requirements.txt
```

## Basic Usage

```bash
# Single URL testing
python3 xsstrike.py -u "http://example.com/search?q=test"

# POST parameter testing
python3 xsstrike.py -u "http://example.com/contact" --data "name=test&email=test@test.com&message=test"

# Cookie-based testing
python3 xsstrike.py -u "http://example.com" --cookie "sessionid=abc123"

# Custom headers
python3 xsstrike.py -u "http://example.com" --headers "X-Forwarded-For: test"
```

## Advanced Features

```bash
# Crawling mode
python3 xsstrike.py -u "http://example.com" --crawl

# Skip DOM XSS detection
python3 xsstrike.py -u "http://example.com/page?q=test" --skip-dom

# Custom payload file
python3 xsstrike.py -u "http://example.com/page?q=test" --file-path custom_payloads.txt

# Blind XSS detection
python3 xsstrike.py -u "http://example.com/form" --blind
```

## Output Options

```bash
# Verbose output
python3 xsstrike.py -u "http://example.com/page?q=test" -v

# Save output to file
python3 xsstrike.py -u "http://example.com/page?q=test" --file-path results.txt

# JSON output format
python3 xsstrike.py -u "http://example.com/page?q=test" --json
```

## Fuzzing Parameters

```bash
# Parameter discovery
python3 xsstrike.py -u "http://example.com/page" --params

# Fuzzing with custom parameters
python3 xsstrike.py -u "http://example.com/page" --params --fuzzer

# Skip parameter analysis
python3 xsstrike.py -u "http://example.com/page?known=param" --skip
```

## Detection Techniques

### Context Analysis
- HTML context detection
- JavaScript context identification  
- CSS context analysis
- Attribute value contexts

### Filter Bypass
- WAF evasion techniques
- Encoding bypasses
- Polyglot payloads
- Browser-specific vectors

### DOM XSS Detection
- Client-side vulnerability identification
- JavaScript source analysis
- Sink detection
- Dynamic analysis capabilities

## Integration

Works well with other web testing tools:
- Burp Suite extensions
- OWASP ZAP integration
- Custom script integration
- Automated pipeline inclusion
