# nbtscan - NetBIOS Name Scanner

Fast NetBIOS name scanner for Windows network reconnaissance and enumeration.

## Installation

```bash
# Ubuntu/Debian/Kali
apt install nbtscan

# From source
wget http://www.unixwiz.net/tools/nbtscan-source-1.0.35.tgz
tar -xzf nbtscan-source-1.0.35.tgz
cd nbtscan-1.0.35
make
make install
```

## Basic Scanning

```bash
# Single host scan
nbtscan 192.168.1.100

# Network range scan
nbtscan 192.168.1.0/24

# Multiple ranges
nbtscan 192.168.1.0/24 10.0.0.0/8

# Custom range
nbtscan 192.168.1.1-254
```

## Output Formats

```bash
# Verbose output
nbtscan -v 192.168.1.0/24

# Human readable format
nbtscan -r 192.168.1.0/24

# Tab separated output
nbtscan -s , 192.168.1.0/24

# Custom separator
nbtscan -s ";" 192.168.1.0/24

# Headers in output
nbtscan -h 192.168.1.0/24
```

## Performance Options

```bash
# Timeout adjustment (milliseconds)
nbtscan -t 2000 192.168.1.0/24

# Custom UDP port
nbtscan -p 137 192.168.1.0/24

# Source port specification
nbtscan -s 1024 192.168.1.0/24

# Multiple retries
nbtscan -m 3 192.168.1.0/24
```

## Information Extraction

```bash
# Show MAC addresses
nbtscan -v 192.168.1.0/24 | grep "MAC"

# Extract computer names only
nbtscan -r 192.168.1.0/24 | awk '{print $2}'

# Show workgroup information
nbtscan -v 192.168.1.0/24 | grep "WORKGROUP\|DOMAIN"

# Identify servers
nbtscan -r 192.168.1.0/24 | grep "SERVER"
```

## Advanced Usage

### Service identification
```bash
#!/bin/bash
# Enhanced nbtscan with service detection
TARGET_RANGE="192.168.1.0/24"

echo "NetBIOS scan for $TARGET_RANGE"
nbtscan -r $TARGET_RANGE > nbt_results.txt

echo "Processing results..."
while read line; do
    IP=$(echo $line | awk '{print $1}')
    NAME=$(echo $line | awk '{print $2}')
    
    if [[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Host: $IP ($NAME)"
        
        # Check for common services
        nmap -p 139,445 -sT $IP --open 2>/dev/null | grep open
    fi
done < nbt_results.txt
```

### Network mapping script
```bash
#!/bin/bash
TARGET=$1

echo "NetBIOS enumeration for $TARGET"

# Basic scan
echo "=== Basic NetBIOS Information ==="
nbtscan -r $TARGET

echo -e "\n=== Detailed NetBIOS Information ==="
nbtscan -v $TARGET

echo -e "\n=== Extracting Key Information ==="

# Computer names
echo "Computer Names:"
nbtscan -r $TARGET | grep -v "Doing NBT name scan" | awk '{print $2}' | sort -u

# IP addresses with names
echo -e "\nIP to Name Mapping:"
nbtscan -r $TARGET | grep -v "Doing NBT name scan" | awk '{print $1 " -> " $2}'

# MAC addresses
echo -e "\nMAC Addresses:"
nbtscan -v $TARGET | grep "MAC Address" | sort -u
```

## Output Processing

### Parse results for further enumeration
```bash
#!/bin/bash
# Extract active NetBIOS hosts for additional scanning

SCAN_RESULTS="nbt_scan.txt"
nbtscan -r 192.168.1.0/24 > $SCAN_RESULTS

# Extract IP addresses
grep -v "Doing NBT name scan" $SCAN_RESULTS | awk '{print $1}' > active_hosts.txt

# Extract hostnames  
grep -v "Doing NBT name scan" $SCAN_RESULTS | awk '{print $2}' > hostnames.txt

# Create target list for enum4linux
cat active_hosts.txt | while read host; do
    echo "enum4linux $host"
done > enum_commands.txt

echo "Found $(wc -l < active_hosts.txt) NetBIOS enabled hosts"
```

### Generate reconnaissance report
```bash
#!/bin/bash
TARGET_NETWORK="192.168.1.0/24"
REPORT_FILE="netbios_report.txt"

echo "NetBIOS Reconnaissance Report" > $REPORT_FILE
echo "Network: $TARGET_NETWORK" >> $REPORT_FILE
echo "Scan Date: $(date)" >> $REPORT_FILE
echo "===============================" >> $REPORT_FILE

# Perform scan
nbtscan -v $TARGET_NETWORK >> $REPORT_FILE

echo -e "\n\nSummary:" >> $REPORT_FILE
echo "=======" >> $REPORT_FILE

# Count active hosts
ACTIVE_HOSTS=$(nbtscan -r $TARGET_NETWORK | grep -v "Doing NBT name scan" | wc -l)
echo "Active NetBIOS hosts: $ACTIVE_HOSTS" >> $REPORT_FILE

# Extract unique workgroups
echo -e "\nWorkgroups/Domains found:" >> $REPORT_FILE
nbtscan -v $TARGET_NETWORK | grep -o "<GROUP>" | sort -u >> $REPORT_FILE

echo "Report saved to $REPORT_FILE"
```

## Integration Examples

### With nmap for comprehensive scanning
```bash
#!/bin/bash
TARGET="192.168.1.0/24"

# NetBIOS discovery
echo "Stage 1: NetBIOS Discovery"
nbtscan -r $TARGET | grep -v "Doing NBT name scan" | awk '{print $1}' > netbios_hosts.txt

# Port scanning of NetBIOS hosts
echo "Stage 2: Port Scanning"
nmap -iL netbios_hosts.txt -p 135,139,445 -sS -O --script smb-os-discovery > detailed_scan.txt

# SMB enumeration
echo "Stage 3: SMB Enumeration"  
for host in $(cat netbios_hosts.txt); do
    echo "Enumerating $host..."
    enum4linux $host > enum_$host.txt 2>/dev/null &
done
wait
```

### With smbclient for share enumeration
```bash
#!/bin/bash
# Combine nbtscan with smbclient for share discovery

# Get NetBIOS enabled hosts
nbtscan -r 192.168.1.0/24 | grep -v "Doing NBT name scan" | awk '{print $1}' > hosts.txt

# Test null session access
for host in $(cat hosts.txt); do
    echo "Testing $host for null session access..."
    smbclient -L //$host -N 2>/dev/null && echo "$host allows null sessions"
done
```

## Common NetBIOS Name Types

Understanding NBT name suffixes:
- `<00>` - Workstation Service
- `<03>` - Messenger Service  
- `<06>` - RAS Server Service
- `<20>` - File Server Service
- `<21>` - RAS Client Service
- `<1B>` - Domain Master Browser
- `<1C>` - Domain Controller
- `<1D>` - Master Browser
- `<1E>` - Browser Service Elections

## Troubleshooting

```bash
# Check if NetBIOS is enabled
nbtscan -p 137 192.168.1.100

# Increase timeout for slow networks
nbtscan -t 5000 192.168.1.0/24

# Verbose debugging
nbtscan -v -d 192.168.1.100
```

Fast and reliable tool for initial Windows network reconnaissance and NetBIOS service discovery.
