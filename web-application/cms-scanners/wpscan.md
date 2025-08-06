# WPScan - WordPress Security Scanner

Comprehensive WordPress vulnerability scanner for identifying security weaknesses.

## Installation

```bash
# Ruby gem installation
gem install wpscan

# Docker installation
docker pull wpscanteam/wpscan

# Ubuntu/Debian
apt install wpscan
```

## Basic Usage

```bash
# Basic WordPress scan
wpscan --url http://example.com

# Enumerate users
wpscan --url http://example.com --enumerate u

# Enumerate vulnerable plugins
wpscan --url http://example.com --enumerate vp

# Enumerate vulnerable themes
wpscan --url http://example.com --enumerate vt

# All enumerations
wpscan --url http://example.com --enumerate u,vp,vt,tt,cb,dbe
```

## Authentication Testing

```bash
# Brute force attack
wpscan --url http://example.com --passwords passwords.txt --usernames admin,administrator

# XML-RPC brute force
wpscan --url http://example.com --password-attack xmlrpc --passwords rockyou.txt

# Login form brute force
wpscan --url http://example.com --password-attack wp-login --passwords wordlist.txt
```

## Advanced Options

```bash
# API token for vulnerability data
wpscan --url http://example.com --api-token YOUR_TOKEN

# Custom user agent
wpscan --url http://example.com --user-agent "Custom-Agent/1.0"

# Request throttling
wpscan --url http://example.com --throttle 500

# Proxy usage
wpscan --url http://example.com --proxy 127.0.0.1:8080
```

## Output Formats

```bash
# JSON output
wpscan --url http://example.com --format json

# CLI output
wpscan --url http://example.com --format cli

# Save to file
wpscan --url http://example.com --output results.txt
```

## Enumeration Options

### Users (`u`)
- Author enumeration via posts
- Login enumeration
- User ID brute forcing

### Plugins (`p`)
- Active plugin detection
- Popular plugin enumeration
- Vulnerable plugin identification

### Themes (`t`)
- Active theme detection
- Popular theme enumeration
- Vulnerable theme identification

### Timthumbs (`tt`)
- Timthumb file enumeration
- Version detection
- Vulnerability assessment

## Configuration Files

```bash
# Custom config file
wpscan --url http://example.com --config-file custom.conf

# Ignore SSL errors
wpscan --url https://example.com --disable-tls-checks

# Follow redirects
wpscan --url http://example.com --follow-redirects
```

## Database Updates

```bash
# Update vulnerability database
wpscan --update

# Check version
wpscan --version
```

## Integration

- CI/CD pipeline integration
- Automated security testing
- Vulnerability management systems
- Custom script integration

Regularly updated vulnerability database ensures current threat detection.
