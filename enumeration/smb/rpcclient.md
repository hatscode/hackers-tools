# rpcclient - RPC Client for Windows Systems

Command-line tool for executing client-side MS-RPC functions against Windows systems.

## Installation

```bash
# Ubuntu/Debian/Kali (part of samba-common-bin)
apt install samba-common-bin

# CentOS/RHEL
yum install samba-client

# Manual compilation
wget https://download.samba.org/pub/samba/stable/samba-4.x.x.tar.gz
tar -xzf samba-4.x.x.tar.gz
cd samba-4.x.x
./configure && make && make install
```

## Connection Methods

```bash
# Anonymous/null session
rpcclient -U "" -N 192.168.1.100

# Guest account
rpcclient -U "guest" 192.168.1.100

# Authenticated connection
rpcclient -U "username" 192.168.1.100

# Domain authentication
rpcclient -U "DOMAIN\username" 192.168.1.100
```

## User Enumeration

```bash
# Within rpcclient session:
rpcclient $> enumdomusers
rpcclient $> queryuser 0x1f4
rpcclient $> querydispinfo
rpcclient $> enumdomgroups
rpcclient $> querygroup 0x200
```

## User Information Gathering

```bash
# Detailed user info
rpcclient $> queryuser administrator
rpcclient $> queryuser guest

# User SID resolution
rpcclient $> lookupnames administrator
rpcclient $> lookupsids S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX-500

# Password policy
rpcclient $> getdompwinfo

# Account lockout policy
rpcclient $> querydispinfo3
```

## Group Enumeration

```bash
# Enumerate domain groups
rpcclient $> enumdomgroups

# Group membership
rpcclient $> querygroup 0x200
rpcclient $> querygroupmem 0x200

# Local groups
rpcclient $> enumalsgroups domain
rpcclient $> queryaliasmem builtin 0x220
```

## System Information

```bash
# Server information
rpcclient $> srvinfo

# Share enumeration
rpcclient $> netshareenum
rpcclient $> netshareenumall

# Printer information
rpcclient $> enumprinters

# Time information
rpcclient $> getanydcinfo
```

## Trust Relationships

```bash
# Domain trusts
rpcclient $> dsenumdomtrusts

# LSA policy information
rpcclient $> lsaquery

# Domain SID
rpcclient $> lsaenumsid
```

## Registry Operations

```bash
# Registry enumeration
rpcclient $> winreg_enumkeys HKLM
rpcclient $> winreg_enumvals HKLM

# Registry queries
rpcclient $> winreg_queryvalue HKLM SOFTWARE\Microsoft\Windows\CurrentVersion ProductName
```

## Service Management

```bash
# Service enumeration
rpcclient $> svcctl_enum_services

# Service queries
rpcclient $> svcctl_query_service Spooler

# Service control
rpcclient $> svcctl_start_service ServiceName
rpcclient $> svcctl_stop_service ServiceName
```

## SAM Database Access

```bash
# SAM enumeration (requires high privileges)
rpcclient $> samlookupnames domain administrator
rpcclient $> samquerysecobj domain
rpcclient $> samlookupids domain 500 501 502
```

## Automated Enumeration Scripts

### Basic enumeration script
```bash
#!/bin/bash
TARGET=$1
echo "RPC enumeration for $TARGET"

echo -e "enumdomusers\nquit" | rpcclient -U "" -N $TARGET
echo -e "enumdomgroups\nquit" | rpcclient -U "" -N $TARGET  
echo -e "srvinfo\nquit" | rpcclient -U "" -N $TARGET
echo -e "netshareenum\nquit" | rpcclient -U "" -N $TARGET
```

### User details extraction
```bash
#!/bin/bash
TARGET=$1

# Get user list
USERS=$(echo -e "enumdomusers\nquit" | rpcclient -U "" -N $TARGET | grep -o 'user:\[.*\]' | cut -d'[' -f2 | cut -d']' -f1)

for user in $USERS; do
    echo "Details for $user:"
    echo -e "queryuser $user\nquit" | rpcclient -U "" -N $TARGET
done
```

## Common RPC Functions

### User Management
- `createuser` - Create user account
- `deleteuser` - Delete user account
- `setuserinfo` - Modify user information
- `setuserinfo2` - Advanced user modification

### Password Operations
- `chgpasswd` - Change user password
- `chgpasswd2` - Advanced password change
- `setuserinfo` - Set password attributes

### Administrative Functions
- `netlogon` - Network logon operations
- `lsarpc` - LSA RPC functions
- `samr` - SAM RPC functions
- `srvsvc` - Server service functions

## Integration with Other Tools

Combine with:
- `enum4linux` for comprehensive enumeration
- `smbclient` for file system access
- `crackmapexec` for credential spraying
- `impacket` suite for advanced operations

## Security Considerations

- Null sessions may be disabled on newer systems
- Requires port 135 (RPC endpoint mapper) access
- May trigger security monitoring systems
- Results depend on target system hardening level
