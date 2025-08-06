# SecLists - Security Testing Wordlists

Comprehensive collection of wordlists for security testing and fuzzing.

## Installation

```bash
# Clone repository
git clone https://github.com/danielmiessler/SecLists.git
cd SecLists

# Download ZIP
wget https://github.com/danielmiessler/SecLists/archive/master.zip
unzip master.zip
```

## Directory Structure

### Discovery
Web content discovery wordlists:
```bash
# Common directories and files
SecLists/Discovery/Web-Content/common.txt
SecLists/Discovery/Web-Content/big.txt
SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Technology-specific paths
SecLists/Discovery/Web-Content/CMS/
SecLists/Discovery/Web-Content/api/
SecLists/Discovery/Web-Content/Apache.fuzz.txt
```

### Passwords
Password lists for brute force attacks:
```bash
# Common passwords
SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
SecLists/Passwords/Common-Credentials/best1050.txt

# Default credentials
SecLists/Passwords/Default-Credentials/
SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Usernames
Username enumeration wordlists:
```bash
# Common usernames
SecLists/Usernames/Names/names.txt
SecLists/Usernames/top-usernames-shortlist.txt

# Admin usernames
SecLists/Usernames/Honeypot-Captures/multiplesources-users-fabian-fingerle.de.txt
```

### Fuzzing
Payloads for various injection types:
```bash
# SQL injection
SecLists/Fuzzing/Databases/

# XSS payloads
SecLists/Fuzzing/XSS/

# Command injection
SecLists/Fuzzing/command-injection-commix.txt

# Local file inclusion
SecLists/Fuzzing/LFI/
```

## Usage Examples

### Directory Enumeration
```bash
# With Gobuster
gobuster dir -u http://example.com -w SecLists/Discovery/Web-Content/common.txt

# With Dirb
dirb http://example.com SecLists/Discovery/Web-Content/big.txt

# With Ffuf
ffuf -u http://example.com/FUZZ -w SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### Password Attacks
```bash
# Hydra SSH brute force
hydra -L SecLists/Usernames/top-usernames-shortlist.txt -P SecLists/Passwords/Common-Credentials/best1050.txt ssh://target

# Hashcat dictionary attack
hashcat -m 0 hashes.txt SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### Parameter Fuzzing
```bash
# Wfuzz parameter discovery
wfuzz -w SecLists/Discovery/Web-Content/burp-parameter-names.txt "http://example.com/page?FUZZ=test"

# Ffuf POST parameter fuzzing
ffuf -w SecLists/Discovery/Web-Content/burp-parameter-names.txt -X POST -d "FUZZ=test" -u http://example.com/login
```

## Specialized Lists

### IoT Wordlists
Device-specific passwords and configurations

### Pattern Databases
Regular expressions for sensitive data detection

### Misconfiguration Payloads
Common misconfigurations and default settings

### Protocol-Specific Lists
SNMP, DNS, and other protocol enumeration lists

Regular updates ensure current threat landscape coverage.
