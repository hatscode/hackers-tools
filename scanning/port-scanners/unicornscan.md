# Unicornscan - Information Gathering Engine

Flexible port scanner with advanced packet manipulation capabilities.

## Installation

```bash
# Ubuntu/Debian
apt-get install unicornscan

# From source
git clone https://github.com/dneufeld/unicornscan
cd unicornscan
./configure
make
sudo make install
```

## Basic Usage

```bash
# TCP connect scan
unicornscan -mT 192.168.1.1:1-1000

# UDP scan
unicornscan -mU 192.168.1.1:1-1000

# ICMP scan
unicornscan -mI 192.168.1.0/24

# Custom packet rate
unicornscan -r 300 -mT 192.168.1.1:1-65535
```

## Advanced Features

```bash
# Custom payload
unicornscan -mT -Iv 192.168.1.1:80 -l payload.txt

# OS fingerprinting
unicornscan -mT -O 192.168.1.1

# Verbose output
unicornscan -v -mT 192.168.1.1:1-1000

# Custom interface
unicornscan -i eth0 -mT 192.168.1.1
```

## Output Formats

```bash
# XML output
unicornscan -mT 192.168.1.1 > results.xml

# Custom format strings
unicornscan -mT 192.168.1.1 -f "%s:%d %T\n"
```

## Packet Crafting

Allows detailed packet customization including:
- Custom TCP flags
- Source address spoofing  
- Fragment handling
- TTL manipulation

## Use Cases

Particularly useful for IDS evasion testing and custom network analysis.
