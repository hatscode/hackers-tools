# smbclient - SMB/CIFS Client Tool

Interactive SMB client for accessing Windows shares and file systems.

## Installation

```bash
# Ubuntu/Debian/Kali
apt install smbclient

# CentOS/RHEL
yum install samba-client

# From source
git clone https://github.com/samba-team/samba.git
cd samba
./configure && make && make install
```

## Basic Connection

```bash
# List shares
smbclient -L //192.168.1.100 -U guest

# Anonymous access
smbclient -L //192.168.1.100 -N

# Connect to specific share
smbclient //192.168.1.100/sharename -U username

# Connect with password
smbclient //192.168.1.100/C$ -U administrator%password123
```

## Authentication Methods

```bash
# Interactive password prompt
smbclient //192.168.1.100/share -U administrator

# Password on command line
smbclient //192.168.1.100/share -U administrator%password

# Hash authentication
smbclient //192.168.1.100/share -U administrator --pw-nt-hash NTHASH

# Domain authentication
smbclient //192.168.1.100/share -U DOMAIN\\username%password

# Kerberos authentication
smbclient //192.168.1.100/share -k -U username@DOMAIN.COM
```

## File Operations

```bash
# Within smbclient session:
smb: \> ls                    # List files
smb: \> cd directory          # Change directory
smb: \> pwd                   # Current directory
smb: \> dir *.txt            # List specific files

# File transfer
smb: \> get filename.txt      # Download file
smb: \> put localfile.txt     # Upload file
smb: \> mget *.doc           # Download multiple files
smb: \> mput *.pdf           # Upload multiple files

# File management
smb: \> rm filename.txt       # Delete file
smb: \> mkdir newdir         # Create directory
smb: \> rmdir emptydir       # Remove directory
```

## Batch Operations

```bash
# Execute commands from file
smbclient //192.168.1.100/share -U user -c "ls; pwd; get important.txt"

# Multiple commands
smbclient //192.168.1.100/share -U user -c "cd documents; ls; mget *.docx"

# Recursive download
smbclient //192.168.1.100/share -U user -c "prompt OFF; recurse ON; mget *"
```

## Advanced Features

```bash
# Binary mode transfer
smb: \> binary

# ASCII mode transfer  
smb: \> ascii

# Archive attribute handling
smb: \> archive 1

# Lowercase filename conversion
smb: \> lowercase

# Show hidden files
smb: \> showacls
```

## Scripted Operations

### Download all files script
```bash
#!/bin/bash
TARGET="//192.168.1.100/share"
USER="administrator"
PASS="password123"

smbclient "$TARGET" -U "$USER%$PASS" -c "prompt OFF; recurse ON; mget *"
```

### Upload backup script
```bash
#!/bin/bash
TARGET="//192.168.1.100/backup"
USER="backupuser"
PASS="backuppass"

smbclient "$TARGET" -U "$USER%$PASS" -c "cd daily; lcd /home/user/backup; mput *"
```

### Directory listing script
```bash
#!/bin/bash
TARGET=$1
USER=$2
PASS=$3

echo "Listing shares on $TARGET"
smbclient -L "$TARGET" -U "$USER%$PASS"

echo -e "\nListing C$ contents:"
smbclient "//$TARGET/C$" -U "$USER%$PASS" -c "ls"
```

## Information Gathering

```bash
# System information
smbclient //192.168.1.100/IPC$ -U user -c "print; sysinfo"

# Share permissions
smbclient -L //192.168.1.100 -U user --option='client min protocol=NT1'

# Extended attributes
smb: \> eainfo filename.txt

# Access control lists
smb: \> getfacl filename.txt
```

## Protocol Versions

```bash
# Force SMB1
smbclient //server/share -U user --option='client min protocol=NT1' --option='client max protocol=NT1'

# Force SMB2
smbclient //server/share -U user --option='client min protocol=SMB2'

# Force SMB3
smbclient //server/share -U user --option='client min protocol=SMB3'
```

## Debugging and Troubleshooting

```bash
# Debug levels
smbclient //server/share -U user -d 3

# Show protocol negotiation
smbclient //server/share -U user --option='log level=2'

# Connection timeout
smbclient //server/share -U user --option='timeout=30'

# Disable encryption
smbclient //server/share -U user --option='client signing=disabled'
```

## Common Administrative Tasks

### File system audit
```bash
# Find sensitive files
smbclient //server/share -U admin -c "recurse ON; ls *password*; ls *secret*; ls *.key"

# Check file permissions
smbclient //server/share -U admin -c "allinfo filename.txt"

# Backup critical files
smbclient //server/share -U admin -c "cd /important; prompt OFF; mget *"
```

### System enumeration via shares
```bash
# Check system files
smbclient //server/C$ -U admin -c "cd Windows\\System32; ls *.exe | head -20"

# Registry access
smbclient //server/C$ -U admin -c "cd Windows\\System32\\config; ls"

# User profiles
smbclient //server/C$ -U admin -c "cd Users; ls"
```

## Integration Examples

Works effectively with:
- `enum4linux` for initial reconnaissance
- `smbmap` for permission mapping  
- `crackmapexec` for credential validation
- `impacket` tools for advanced operations

## Performance Optimization

```bash
# Increase buffer sizes
smbclient //server/share -U user --option='socket options=TCP_NODELAY IPTOS_LOWDELAY'

# Connection pooling
smbclient //server/share -U user --option='max mux=50'

# Disable opportunistic locking
smbclient //server/share -U user --option='use oplocks=no'
```

Fundamental tool for SMB/CIFS file system access and Windows network enumeration.
