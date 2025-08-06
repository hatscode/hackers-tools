# Wireshark - Network Protocol Analyzer

World's foremost network protocol analyzer for troubleshooting and analysis.

## Installation

```bash
# Ubuntu/Debian
apt install wireshark

# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# GUI version
wireshark

# Command line version
tshark
```

## Basic Interface Usage

### Capture Filters
Applied before packet capture to limit data collection.

```bash
# Host-specific capture
host 192.168.1.1

# Protocol filtering
tcp port 80
udp port 53

# Network range
net 192.168.1.0/24

# Complex filters
host 192.168.1.1 and tcp port 443
```

### Display Filters
Applied to captured data for analysis.

```bash
# Protocol analysis
http
dns
tcp.port == 443

# IP-based filtering
ip.addr == 192.168.1.1
ip.src == 10.0.0.1

# Content-based filtering
http contains "password"
tcp.payload contains "admin"
```

## Command Line Analysis

```bash
# Capture to file
tshark -i eth0 -w capture.pcap

# Read from file
tshark -r capture.pcap

# Apply filters
tshark -r capture.pcap -Y "http"

# Extract specific fields
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port
```

## Advanced Features

### Statistics
- Protocol hierarchy
- Conversation analysis
- I/O graphs
- Flow analysis

### Decryption
```bash
# SSL/TLS decryption (with private keys)
Edit -> Preferences -> Protocols -> TLS

# WPA/WPA2 decryption
Edit -> Preferences -> Protocols -> IEEE 802.11
```

### Export Objects
- HTTP objects
- SMB files
- FTP transfers
- Email attachments

## Forensics Applications

- Network incident analysis
- Malware traffic analysis
- Data exfiltration detection
- Protocol compliance testing

## Scripting and Automation

Supports Lua scripting for custom analysis and dissector development.
