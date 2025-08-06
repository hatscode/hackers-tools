# Hydra - Network Logon Cracker

Fast network authentication cracker supporting numerous protocols.

## Installation

```bash
# Ubuntu/Debian
apt install hydra

# From source
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra
./configure
make
sudo make install
```

## Basic Usage

```bash
# Single target, single user
hydra -l admin -p password ssh://192.168.1.1

# Multiple users and passwords
hydra -L users.txt -P passwords.txt ssh://192.168.1.1

# Wordlist attack
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
```

## Supported Protocols

```bash
# SSH brute force
hydra -L users.txt -P passwords.txt ssh://target

# FTP authentication
hydra -l anonymous -P passwords.txt ftp://target

# HTTP basic auth
hydra -L users.txt -P passwords.txt http-get://target/admin/

# HTTP form-based
hydra -L users.txt -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# SMB/NetBIOS
hydra -L users.txt -P passwords.txt smb://target

# RDP brute force
hydra -L users.txt -P passwords.txt rdp://target
```

## Advanced Options

```bash
# Threading control
hydra -t 16 -L users.txt -P passwords.txt ssh://target

# Connection timing
hydra -w 60 -L users.txt -P passwords.txt ssh://target

# Exit after first success
hydra -f -l admin -P passwords.txt ssh://target

# Resume previous session
hydra -R
```

## HTTP Form Analysis

```bash
# Analyze login form
hydra -L users.txt -P passwords.txt target http-post-form \
"/login.php:username=^USER^&password=^PASS^&submit=Login:Login Failed"

# With cookies
hydra -L users.txt -P passwords.txt target http-post-form \
"/login.php:user=^USER^&pass=^PASS^:Failed:H=Cookie: security=low; PHPSESSID=abc123"
```

## Output Options

```bash
# Verbose output
hydra -v -L users.txt -P passwords.txt ssh://target

# Save results
hydra -o results.txt -L users.txt -P passwords.txt ssh://target

# Different output formats
hydra -b json -o results.json -L users.txt -P passwords.txt ssh://target
```

## Performance Tuning

```bash
# Increase task limit
hydra -t 64 -L users.txt -P passwords.txt ssh://target

# Connection retries
hydra -c 3 -L users.txt -P passwords.txt ssh://target

# Wait between attempts
hydra -W 1 -L users.txt -P passwords.txt ssh://target
```

## SSL/TLS Support

Most protocols support SSL/TLS variants (add 's' suffix or specify port).
