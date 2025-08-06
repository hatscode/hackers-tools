# Masscan - High Speed Port Scanner

Internet-scale port scanner capable of scanning the entire Internet in under 6 minutes.

## Installation

```bash
# From source
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install

# Ubuntu/Debian
apt-get install masscan
```

## Basic Commands

```bash
# Scan specific ports
masscan -p80,443 192.168.1.0/24

# Scan port range
masscan -p1-1000 target.com

# High-speed scan
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Output formats
masscan -p80 192.168.1.0/24 -oX output.xml
```

## Performance Tuning

```bash
# Adjust packet rate
masscan --rate 10000 -p80 target_range

# Custom source port
masscan --source-port 61000 -p80 target.com

# Exclude ranges
masscan -p80 0.0.0.0/0 --exclude 192.168.1.0/24
```

## Configuration File

```bash
# Create masscan.conf
rate = 1000
output-format = xml
output-status = all
output-filename = scan.xml
ports = 80,443,22,21,25,53,110,993,995
```

## Integration Tips

Works well with nmap for detailed follow-up scans on discovered hosts.

## Warnings

Extremely fast scanning can overwhelm network infrastructure. Start with low rates.
