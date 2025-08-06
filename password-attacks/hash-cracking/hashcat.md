# Hashcat - Advanced Password Recovery

High-performance password cracking tool supporting numerous hash algorithms.

## Installation

```bash
# Ubuntu/Debian
apt install hashcat

# Download binary
wget https://hashcat.net/files/hashcat-6.2.6.tar.gz
tar -xzf hashcat-6.2.6.tar.gz
cd hashcat-6.2.6
```

## Basic Usage

```bash
# Identify hash type
hashcat --help | grep -i md5

# Dictionary attack
hashcat -m 0 hashes.txt rockyou.txt

# Brute force attack
hashcat -m 0 hashes.txt -a 3 ?a?a?a?a?a?a

# Rule-based attack
hashcat -m 0 hashes.txt wordlist.txt -r rules/best64.rule
```

## Hash Types

```bash
# Common hash modes
-m 0    MD5
-m 100  SHA1
-m 1400 SHA2-256
-m 1800 sha512crypt
-m 3200 bcrypt
-m 13100 Kerberos 5
-m 18200 Kerberos 5, etype 18
```

## Attack Modes

```bash
# Straight (dictionary) attack
hashcat -a 0 hashes.txt wordlist.txt

# Combination attack
hashcat -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Brute-force attack
hashcat -a 3 hashes.txt ?d?d?d?d?d?d

# Hybrid wordlist + mask
hashcat -a 6 hashes.txt wordlist.txt ?d?d?d

# Hybrid mask + wordlist
hashcat -a 7 hashes.txt ?d?d?d wordlist.txt
```

## Character Sets

```bash
# Built-in charsets
?l  lowercase letters (a-z)
?u  uppercase letters (A-Z)
?d  digits (0-9)
?s  special characters
?a  all characters (?l?u?d?s)
?b  all bytes (0x00-0xff)

# Custom charset
hashcat -1 ?l?d hashes.txt -a 3 ?1?1?1?1?1?1
```

## Performance Tuning

```bash
# Workload profile
-w 1  Low (desktop use)
-w 2  Default
-w 3  High (dedicated cracking)
-w 4  Nightmare (headless systems)

# OpenCL device selection
-d 1,2  Use devices 1 and 2
-D 1    Use OpenCL platform 1

# Benchmark mode
hashcat -b -m 0
```

## Rules and Mutations

```bash
# Popular rule sets
-r rules/best64.rule
-r rules/dive.rule
-r rules/leetspeak.rule

# Generate rules
hashcat --generate-rules=10000 > custom.rule
```
