# Joomscan - Joomla Vulnerability Scanner

Specialized vulnerability scanner for Joomla content management system.

## Installation

```bash
# Clone repository
git clone https://github.com/OWASP/joomscan.git
cd joomscan

# Make executable
chmod +x joomscan.pl

# Install dependencies
cpan LWP::UserAgent
cpan HTTP::Request
cpan JSON
```

## Basic Usage

```bash
# Basic Joomla scan
perl joomscan.pl --url http://example.com

# Enumerate components
perl joomscan.pl --url http://example.com --enumerate-components

# Cookie-based scan
perl joomscan.pl --url http://example.com --cookie "sessionid=abc123"

# Random user agent
perl joomscan.pl --url http://example.com --random-agent
```

## Advanced Scanning

```bash
# Update database
perl joomscan.pl --update

# Specify timeout
perl joomscan.pl --url http://example.com --timeout 10

# Proxy usage
perl joomscan.pl --url http://example.com --proxy http://127.0.0.1:8080

# Verbose output
perl joomscan.pl --url http://example.com --verbose
```

## Detection Capabilities

### Version Fingerprinting
- Joomla version identification
- Build number detection
- Update status verification

### Component Scanning
- Third-party component enumeration
- Vulnerable component identification
- Version checking for components

### Configuration Issues
- Admin interface exposure
- Backup file detection
- Configuration file leakage

### Security Headers
- Security header analysis
- Missing protection mechanisms
- SSL/TLS configuration review

## Vulnerability Database

### Known Exploits
- Public exploit availability
- CVE cross-references
- Security advisory matching

### Common Vulnerabilities
- SQL injection points
- File upload vulnerabilities
- Authentication bypasses
- Cross-site scripting issues

## Output Formats

```bash
# HTML report
perl joomscan.pl --url http://example.com --output-file report.html

# Text output
perl joomscan.pl --url http://example.com > results.txt

# JSON format
perl joomscan.pl --url http://example.com --json-output
```

## Integration Features

### Automation Support
- Command line interface
- Scriptable execution
- Batch processing capabilities

### CI/CD Integration
- Automated security testing
- Pipeline integration
- Continuous monitoring

## Remediation Guidance

Provides specific recommendations for:
- Version upgrades
- Component updates
- Configuration hardening
- Security best practices

Part of OWASP project ensuring reliable vulnerability detection for Joomla installations.
