# Zmap - Internet-Wide Network Scanner

Single packet network scanner designed for Internet-wide network surveys.

## Installation

```bash
# Ubuntu/Debian
apt-get install zmap

# From source
git clone https://github.com/zmap/zmap.git
cd zmap
cmake .
make
sudo make install
```

## Basic Scanning

```bash
# Scan single port across Internet
zmap -p 80

# Scan specific network
zmap -p 443 192.168.1.0/24

# Multiple target specification
zmap -p 22 -B 10M 10.0.0.0/8

# Custom probe module
zmap -M icmp_echoscan
```

## Output Options

```bash
# JSON output
zmap -p 80 -o results.json -f json

# CSV format
zmap -p 443 -o results.csv -f csv

# Extended fields
zmap -p 80 -f "saddr,daddr,sport,dport,seqnum,acknum,window"
```

## Advanced Features

```bash
# Custom source port range
zmap -p 80 -s 61000-65000

# Bandwidth limiting
zmap -p 80 -B 1M

# Probe rate control
zmap -p 80 -r 1000

# Blacklist file
zmap -p 80 -b blacklist.txt
```

## Probe Modules

- tcp_synscan: TCP SYN scanning
- icmp_echoscan: ICMP echo requests
- udp: UDP probing
- dns: DNS queries

## Research Applications

Originally developed for academic network measurement studies.
