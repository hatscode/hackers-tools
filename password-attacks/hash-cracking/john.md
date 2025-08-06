# John the Ripper - Password Security Auditing Tool

Fast password cracker with support for many ciphertext formats.

## Installation

```bash
# Ubuntu/Debian
apt install john

# Jumbo version (extended functionality)
git clone https://github.com/magnumripper/JohnTheRipper.git
cd JohnTheRipper/src
./configure
make -j4
```

## Basic Usage

```bash
# Simple password cracking
john passwords.txt

# Specify wordlist
john --wordlist=rockyou.txt passwords.txt

# Show cracked passwords
john --show passwords.txt

# Resume interrupted session
john --restore
```

## Hash Format Detection

```bash
# Identify hash format
john --list=formats | grep -i md5

# Format-specific cracking
john --format=raw-md5 hashes.txt
john --format=nt passwords.txt
```

## Attack Modes

```bash
# Single crack mode (default)
john passwords.txt

# Dictionary mode
john --wordlist=dict.txt passwords.txt

# Incremental mode (brute force)
john --incremental passwords.txt

# External mode (custom rules)
john --external=mode passwords.txt
```

## Rules and Mangling

```bash
# Apply rules
john --rules passwords.txt

# Specific rule set
john --rules=Wordlist passwords.txt

# Custom rules in john.conf
[List.Rules:Custom]
: 
c $1 $2 $3
```

## Hash Extraction

```bash
# Shadow file passwords
unshadow /etc/passwd /etc/shadow > passwords.txt

# ZIP file passwords
zip2john archive.zip > hash.txt

# PDF passwords
pdf2john document.pdf > hash.txt

# SSH private keys
ssh2john id_rsa > hash.txt
```

## Performance Options

```bash
# Fork processes
john --fork=4 passwords.txt

# Session management
john --session=mysession passwords.txt

# Status check
john --status=mysession
```

## Configuration

```bash
# Custom wordlist paths
echo "/path/to/wordlist" >> ~/.john/john.conf

# Markov mode parameters
john --markov=200 --max-len=8 passwords.txt
```
