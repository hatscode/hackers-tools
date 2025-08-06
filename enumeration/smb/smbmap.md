# smbmap - SMB Enumeration Tool

Advanced SMB share enumeration tool with authentication and permission mapping.

## Installation

```bash
# Python pip installation
pip install smbmap

# Ubuntu/Debian
apt install smbmap

# From source
git clone https://github.com/ShawnDEvans/smbmap.git
cd smbmap
python setup.py install
```

## Basic Usage

```bash
# Basic enumeration
smbmap -H 192.168.1.100

# Guest access
smbmap -H 192.168.1.100 -u guest

# Null session
smbmap -H 192.168.1.100 -u '' -p ''
```

## Authentication Options

```bash
# Username and password
smbmap -H 192.168.1.100 -u administrator -p password123

# Domain authentication
smbmap -H 192.168.1.100 -u 'DOMAIN\username' -p 'password'

# Hash authentication
smbmap -H 192.168.1.100 -u administrator -p 'LM:NT_HASH'

# Kerberos authentication
smbmap -H 192.168.1.100 -u username -p password -d DOMAIN.COM
```

## Share Operations

```bash
# List shares and permissions
smbmap -H 192.168.1.100 -u administrator -p password123

# Recursive directory listing
smbmap -H 192.168.1.100 -u administrator -p password123 -R

# Specific share access
smbmap -H 192.168.1.100 -u administrator -p password123 -s 'C$'

# Pattern-based file search
smbmap -H 192.168.1.100 -u administrator -p password123 -R --include='*.txt'
```

## File Operations

```bash
# Download file
smbmap -H 192.168.1.100 -u administrator -p password123 --download 'C$\temp\file.txt'

# Upload file
smbmap -H 192.168.1.100 -u administrator -p password123 --upload '/local/file.txt' 'C$\temp\file.txt'

# Delete file
smbmap -H 192.168.1.100 -u administrator -p password123 --delete 'C$\temp\file.txt'

# Create directory
smbmap -H 192.168.1.100 -u administrator -p password123 --mkdir 'C$\temp\newdir'
```

## Command Execution

```bash
# Execute command
smbmap -H 192.168.1.100 -u administrator -p password123 -x 'whoami'

# PowerShell execution
smbmap -H 192.168.1.100 -u administrator -p password123 -X 'Get-Process'

# Command with output file
smbmap -H 192.168.1.100 -u administrator -p password123 -x 'dir C:\' --mode exec
```

## Batch Operations

```bash
# Multiple hosts from file
smbmap -H hosts.txt -u administrator -p password123

# Host range
smbmap -H 192.168.1.1-254 -u administrator -p password123

# Output to file
smbmap -H 192.168.1.100 -u administrator -p password123 -q > results.txt
```

## Advanced Features

### Permission Analysis
- Read/Write access mapping
- Administrative share identification
- Hidden share discovery
- Permission inheritance analysis

### Content Discovery
- File extension filtering
- Size-based filtering
- Date-based filtering
- Content pattern matching

### Stealth Options
```bash
# Quiet mode
smbmap -H 192.168.1.100 -u administrator -p password123 -q

# Time delays
smbmap -H 192.168.1.100 -u administrator -p password123 --delay 2

# Custom port
smbmap -H 192.168.1.100 -u administrator -p password123 -P 445
```

## Integration

Excellent for:
- Post-exploitation enumeration
- Lateral movement preparation
- Data exfiltration planning
- Privilege escalation reconnaissance

Works well alongside enum4linux, rpcclient, and crackmapexec for comprehensive SMB assessment.
