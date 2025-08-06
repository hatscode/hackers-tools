# Enum4linux - SMB Enumeration Tool

Linux alternative to enum.exe for enumerating SMB shares and Windows network information.

## Installation

```bash
# Ubuntu/Debian
apt install enum4linux

# From source
git clone https://github.com/CiscoCXSecurity/enum4linux.git
cd enum4linux
chmod +x enum4linux.pl
```

## Basic Usage

```bash
# Basic enumeration
enum4linux 192.168.1.100

# Detailed enumeration
enum4linux -a 192.168.1.100

# Specific checks only
enum4linux -U -S -P 192.168.1.100
```

## Enumeration Options

```bash
# User enumeration
enum4linux -U 192.168.1.100

# Share enumeration
enum4linux -S 192.168.1.100

# Password policy
enum4linux -P 192.168.1.100

# Group information
enum4linux -G 192.168.1.100

# OS information
enum4linux -o 192.168.1.100
```

## Authentication

```bash
# Null session
enum4linux -u "" -p "" 192.168.1.100

# Guest access
enum4linux -u "guest" -p "" 192.168.1.100

# Authenticated scan
enum4linux -u "username" -p "password" 192.168.1.100

# Domain authentication
enum4linux -u "DOMAIN\\username" -p "password" 192.168.1.100
```

## Advanced Options

```bash
# Custom wordlist for users
enum4linux -u "" -p "" -U -f /path/to/userlist.txt 192.168.1.100

# Verbose output
enum4linux -v 192.168.1.100

# Machine enumeration
enum4linux -M 192.168.1.100

# Printer enumeration
enum4linux -i 192.168.1.100
```

## Information Gathered

### Users and Groups
- Local user accounts
- Domain user enumeration
- Group memberships
- User account properties

### Shares and Permissions
- Available SMB shares
- Share permissions
- Hidden shares
- Administrative shares

### System Information
- Operating system details
- Domain information
- Workgroup membership
- Server role identification

### Security Policies
- Password policies
- Account lockout policies
- Minimum password length
- Password history requirements

## Output Processing

```bash
# Save output to file
enum4linux 192.168.1.100 > enum4linux_output.txt

# Extract usernames only
enum4linux -U 192.168.1.100 | grep "user:" | cut -d: -f2

# Extract share names
enum4linux -S 192.168.1.100 | grep -E "Mapping: OK|Sharename"
```

## Integration

Works well with other SMB tools:
- smbclient for share access
- rpcclient for RPC enumeration
- smbmap for permission mapping
- crackmapexec for credential testing

Essential tool for Windows network penetration testing and SMB reconnaissance.
