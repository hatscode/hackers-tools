# XSSer - Cross Site Scripter

Automatic XSS detection and exploitation tool with multiple attack vectors.

## Installation

```bash
# Ubuntu/Debian
apt install xsser

# From source
git clone https://github.com/epsylon/xsser.git
cd xsser
python3 setup.py install
```

## Basic Usage

```bash
# Single URL testing
xsser --url "http://example.com/search?q=test"

# POST parameter testing
xsser --url "http://example.com/contact" -p "name=test&email=test@test.com&message=test"

# Crawling mode
xsser --url "http://example.com" --auto
```

## Attack Options

```bash
# All attack vectors
xsser --url "http://example.com/search?q=test" --Cem

# Specific vectors
xsser --url "http://example.com/search?q=test" --Ce  # Cookie injection
xsser --url "http://example.com/search?q=test" --Cs  # Script injection
xsser --url "http://example.com/search?q=test" --Cl  # Tag injection
```

## Advanced Features

```bash
# Custom payloads
xsser --url "http://example.com/search?q=test" --payload "<script>alert('XSS')</script>"

# DOM XSS testing
xsser --url "http://example.com/page.html" --dom

# Reverse shell payload
xsser --url "http://example.com/search?q=test" --reverse-check

# Permanent XSS
xsser --url "http://example.com/search?q=test" --tcp-nodelay
```

## Encoding Options

```bash
# URL encoding
xsser --url "http://example.com/search?q=test" --Ue

# Hex encoding
xsser --url "http://example.com/search?q=test" --Hex

# Integer encoding
xsser --url "http://example.com/search?q=test" --Int

# Mixed encoding
xsser --url "http://example.com/search?q=test" --Mix
```

## Bypass Techniques

```bash
# WAF bypass
xsser --url "http://example.com/search?q=test" --ignore-proxy

# Case variation
xsser --url "http://example.com/search?q=test" --Coo

# Character replacement
xsser --url "http://example.com/search?q=test" --Chr
```

## Output Options

```bash
# Verbose output
xsser --url "http://example.com/search?q=test" -v

# XML report
xsser --url "http://example.com/search?q=test" --xml=report.xml

# Export results
xsser --url "http://example.com/search?q=test" --save

# Statistics
xsser --url "http://example.com/search?q=test" --stats
```

## GTK Interface

```bash
# Launch GUI
xsser --gtk
```

## Integration Features

- Proxy support for Burp Suite/ZAP
- Custom header injection
- Cookie manipulation
- Session handling
- Multi-threading support

Comprehensive XSS testing with extensive evasion capabilities.
