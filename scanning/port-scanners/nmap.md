# Nmap - Network Mapper

Advanced port scanner and network discovery tool used by security professionals worldwide.

## Installation

```bash
# Ubuntu/Debian
apt-get install nmap

# CentOS/RHEL
yum install nmap

# Arch Linux
pacman -S nmap
```

## Basic Usage

```bash
# Simple host discovery
nmap 192.168.1.1

# Port range scan
nmap -p 1-1000 target.com

# Service version detection
nmap -sV target.com

# Operating system detection
nmap -O target.com

# Aggressive scan
nmap -A target.com
```

## Advanced Techniques

```bash
# SYN stealth scan
nmap -sS target.com

# UDP scan
nmap -sU target.com

# Script scanning
nmap --script vuln target.com

# Output to file
nmap -oA scan_results target.com
```

## Common Scripts

- http-enum: Enumerate web directories
- smb-vuln-*: SMB vulnerability detection
- ssl-cert: SSL certificate information
- dns-brute: DNS bruteforce

## Legal Notes

Only scan networks you own or have written permission to test. Unauthorized scanning may violate local laws.
