# The Complete Nmap Tutorial Guide

## Table of Contents
1. [What is Nmap?](#what-is-nmap)
2. [How Nmap Works](#how-nmap-works)
3. [Basic Syntax and Installation](#basic-syntax-and-installation)
4. [Host Discovery](#host-discovery)
5. [Port Scanning Techniques](#port-scanning-techniques)
6. [Service and Version Detection](#service-and-version-detection)
7. [Operating System Detection](#operating-system-detection)
8. [Timing and Performance](#timing-and-performance)
9. [Output Formats](#output-formats)
10. [NSE Scripting Engine](#nse-scripting-engine)
11. [Firewall and IDS Evasion](#firewall-and-ids-evasion)
12. [Advanced Features](#advanced-features)
13. [Legal Usage and Best Practices](#legal-usage-and-best-practices)

---

## What is Nmap?

Nmap (Network Mapper) is a free, open-source network discovery and security auditing tool. Originally written by Gordon Lyon (Fyodor), Nmap has become the de facto standard for network reconnaissance and security testing.

**Primary Uses:**
- Network inventory and asset discovery
- Security auditing and vulnerability assessment
- Network troubleshooting and monitoring
- Service uptime monitoring
- Network mapping and topology discovery

**Key Capabilities:**
- Host discovery (finding live systems)
- Port scanning (identifying open/closed ports)
- Service detection (identifying running services)
- Operating system detection
- Vulnerability detection through scripting
- Firewall/filter detection and evasion

---

## How Nmap Works

Nmap operates by sending specially crafted packets to target hosts and analyzing the responses (or lack thereof). The tool uses various scanning techniques based on different TCP/IP behaviors:

### Packet Types Used:
- **TCP SYN packets**: For stealth scanning
- **TCP ACK packets**: For firewall rule detection
- **UDP packets**: For UDP service discovery
- **ICMP packets**: For host discovery
- **ARP requests**: For local network discovery

### Response Analysis:
Nmap interprets responses to determine:
- Port states (open, closed, filtered)
- Service types and versions
- Operating system characteristics
- Network topology and filtering devices

---

## Basic Syntax and Installation

### Installation
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS (with Homebrew)
brew install nmap

# Windows: Download from https://nmap.org/download.html
```

### Basic Syntax
```bash
nmap [Scan Type] [Options] {target specification}
```

### Target Specification Formats:
- Single IP: `192.168.1.1`
- IP range: `192.168.1.1-254`
- CIDR notation: `192.168.1.0/24`
- Hostname: `example.com`
- Multiple targets: `192.168.1.1 192.168.1.5 example.com`

### Simple Examples:
```bash
# Scan a single host
nmap 192.168.1.1

# Scan a subnet
nmap 192.168.1.0/24

# Scan multiple hosts
nmap 192.168.1.1-10
```

---

## Host Discovery

Host discovery determines which hosts are online before performing port scans. This saves time by avoiding scans of inactive hosts.

### `-sL` (List Scan)
**Syntax:** `nmap -sL <targets>`
**Purpose:** Lists targets without sending packets
**Example:** `nmap -sL 192.168.1.0/24`
**Use Case:** Verify target list before scanning

### `-sn` (Ping Scan)
**Syntax:** `nmap -sn <targets>`
**Purpose:** Discovers live hosts without port scanning
**Example:** `nmap -sn 192.168.1.0/24`
**Use Case:** Network inventory, finding active hosts quickly

### `-Pn` (No Ping)
**Syntax:** `nmap -Pn <targets>`
**Purpose:** Skip host discovery, assume all hosts are online
**Example:** `nmap -Pn 192.168.1.1-50`
**Use Case:** Scanning hosts behind firewalls that block ping

### `-PS<port list>` (TCP SYN Ping)
**Syntax:** `nmap -PS80,443,22 <targets>`
**Purpose:** Uses TCP SYN packets to discover hosts
**Example:** `nmap -PS80,443 192.168.1.0/24`
**Use Case:** Discovering hosts when ICMP is blocked

### `-PA<port list>` (TCP ACK Ping)
**Syntax:** `nmap -PA80,443,22 <targets>`
**Purpose:** Uses TCP ACK packets for host discovery
**Example:** `nmap -PA80 192.168.1.0/24`
**Use Case:** Bypassing stateless firewalls

### `-PU<port list>` (UDP Ping)
**Syntax:** `nmap -PU53,161,137 <targets>`
**Purpose:** Uses UDP packets for host discovery
**Example:** `nmap -PU53 192.168.1.0/24`
**Use Case:** Discovering hosts via UDP services

### `-PE` (ICMP Echo Ping)
**Syntax:** `nmap -PE <targets>`
**Purpose:** Uses traditional ICMP echo requests
**Example:** `nmap -PE 192.168.1.0/24`
**Use Case:** Basic host discovery when ICMP is allowed

### `-PP` (ICMP Timestamp Ping)
**Syntax:** `nmap -PP <targets>`
**Purpose:** Uses ICMP timestamp requests
**Example:** `nmap -PP 192.168.1.0/24`
**Use Case:** Alternative when echo requests are blocked

### `-PM` (ICMP Netmask Ping)
**Syntax:** `nmap -PM <targets>`
**Purpose:** Uses ICMP netmask requests
**Example:** `nmap -PM 192.168.1.0/24`
**Use Case:** Another ICMP alternative

### `-PO<protocol list>` (IP Protocol Ping)
**Syntax:** `nmap -PO1,2,4 <targets>`
**Purpose:** Uses IP protocol packets
**Example:** `nmap -PO1 192.168.1.0/24`
**Use Case:** Low-level host discovery

---

## Port Scanning Techniques

Port scanning is Nmap's core functionality, determining which ports are open, closed, or filtered.

### Port States:
- **Open**: Service actively accepting connections
- **Closed**: No service listening, but port accessible
- **Filtered**: Cannot determine if open/closed (firewall blocking)
- **Unfiltered**: Port accessible but state unknown
- **Open|Filtered**: Cannot determine between open/filtered
- **Closed|Filtered**: Cannot determine between closed/filtered

### `-sS` (TCP SYN Scan - Stealth Scan)
**Syntax:** `nmap -sS <targets>`
**Purpose:** Half-open scanning, doesn't complete TCP handshake
**Example:** `nmap -sS 192.168.1.1`
**Use Case:** Default and most popular scan, stealthy and fast

### `-sT` (TCP Connect Scan)
**Syntax:** `nmap -sT <targets>`
**Purpose:** Complete TCP connection to each port
**Example:** `nmap -sT 192.168.1.1`
**Use Case:** When SYN scan not available (non-privileged users)

### `-sU` (UDP Scan)
**Syntax:** `nmap -sU <targets>`
**Purpose:** Scans UDP ports
**Example:** `nmap -sU 192.168.1.1`
**Use Case:** Finding UDP services (DNS, SNMP, DHCP)

### `-sY` (SCTP INIT Scan)
**Syntax:** `nmap -sY <targets>`
**Purpose:** SCTP INIT scan
**Example:** `nmap -sY 192.168.1.1`
**Use Case:** Scanning SCTP services

### `-sN` (TCP Null Scan)
**Syntax:** `nmap -sN <targets>`
**Purpose:** Sends packets with no flags set
**Example:** `nmap -sN 192.168.1.1`
**Use Case:** Firewall evasion, works against some systems

### `-sF` (TCP FIN Scan)
**Syntax:** `nmap -sF <targets>`
**Purpose:** Sends packets with FIN flag set
**Example:** `nmap -sF 192.168.1.1`
**Use Case:** Firewall evasion, stealth scanning

### `-sX` (TCP Xmas Scan)
**Syntax:** `nmap -sX <targets>`
**Purpose:** Sends packets with FIN, PSH, and URG flags
**Example:** `nmap -sX 192.168.1.1`
**Use Case:** Firewall evasion, creative scanning

### `-sA` (TCP ACK Scan)
**Syntax:** `nmap -sA <targets>`
**Purpose:** Maps firewall rule sets
**Example:** `nmap -sA 192.168.1.1`
**Use Case:** Discovering firewall rules, not for finding open ports

### `-sW` (TCP Window Scan)
**Syntax:** `nmap -sW <targets>`
**Purpose:** Uses TCP window field variations
**Example:** `nmap -sW 192.168.1.1`
**Use Case:** Distinguishing open from closed ports on some systems

### `-sM` (TCP Maimon Scan)
**Syntax:** `nmap -sM <targets>`
**Purpose:** Uses FIN/ACK packets
**Example:** `nmap -sM 192.168.1.1`
**Use Case:** Works against some BSD-derived systems

### Port Specification Options

### `-p` (Port Specification)
**Syntax:** `nmap -p <ports> <targets>`
**Examples:**
- `nmap -p 80 192.168.1.1` (single port)
- `nmap -p 80,443,22 192.168.1.1` (multiple ports)
- `nmap -p 1-1000 192.168.1.1` (port range)
- `nmap -p- 192.168.1.1` (all 65535 ports)
- `nmap -p U:53,T:80 192.168.1.1` (UDP and TCP)

### `-F` (Fast Scan)
**Syntax:** `nmap -F <targets>`
**Purpose:** Scans only top 100 most common ports
**Example:** `nmap -F 192.168.1.1`
**Use Case:** Quick scans when time is limited

### `--top-ports`
**Syntax:** `nmap --top-ports <number> <targets>`
**Purpose:** Scans the most common N ports
**Example:** `nmap --top-ports 1000 192.168.1.1`
**Use Case:** Balanced between speed and coverage

---

## Service and Version Detection

Service detection identifies what services are running on open ports and attempts to determine version information.

### `-sV` (Version Detection)
**Syntax:** `nmap -sV <targets>`
**Purpose:** Determines service/version info for open ports
**Example:** `nmap -sV 192.168.1.1`
**Use Case:** Identifying services for security assessment

### `--version-intensity`
**Syntax:** `nmap -sV --version-intensity <0-9> <targets>`
**Purpose:** Controls intensity of version detection (0=light, 9=try all)
**Example:** `nmap -sV --version-intensity 7 192.168.1.1`
**Use Case:** Balancing speed vs. thoroughness

### `--version-light`
**Syntax:** `nmap -sV --version-light <targets>`
**Purpose:** Enables light mode (intensity 2)
**Example:** `nmap -sV --version-light 192.168.1.1`
**Use Case:** Quick version detection

### `--version-all`
**Syntax:** `nmap -sV --version-all <targets>`
**Purpose:** Tries every single probe (intensity 9)
**Example:** `nmap -sV --version-all 192.168.1.1`
**Use Case:** Maximum version detection accuracy

### `--version-trace`
**Syntax:** `nmap -sV --version-trace <targets>`
**Purpose:** Shows detailed version scan activity
**Example:** `nmap -sV --version-trace 192.168.1.1`
**Use Case:** Debugging version detection issues

---

## Operating System Detection

OS detection attempts to determine the target's operating system using TCP/IP stack fingerprinting.

### `-O` (OS Detection)
**Syntax:** `nmap -O <targets>`
**Purpose:** Enables OS detection
**Example:** `nmap -O 192.168.1.1`
**Use Case:** Asset inventory, vulnerability assessment preparation

### `--osscan-limit`
**Syntax:** `nmap -O --osscan-limit <targets>`
**Purpose:** Limit OS detection to promising targets
**Example:** `nmap -O --osscan-limit 192.168.1.0/24`
**Use Case:** Speed up scans of large networks

### `--osscan-guess`
**Syntax:** `nmap -O --osscan-guess <targets>`
**Purpose:** Guess OS more aggressively
**Example:** `nmap -O --osscan-guess 192.168.1.1`
**Use Case:** When confident OS detection needed

### `--max-os-tries`
**Syntax:** `nmap -O --max-os-tries <number> <targets>`
**Purpose:** Set maximum number of OS detection attempts
**Example:** `nmap -O --max-os-tries 2 192.168.1.1`
**Use Case:** Speed up scans by limiting retries

---

## Timing and Performance

Timing templates and performance options control scan speed and network load.

### Timing Templates (`-T<0-5>`)
**Syntax:** `nmap -T<0-5> <targets>`

### `-T0` (Paranoid)
**Purpose:** Very slow scan to avoid IDS detection
**Example:** `nmap -T0 192.168.1.1`
**Use Case:** Maximum stealth, avoid detection

### `-T1` (Sneaky)
**Purpose:** Slow scan to avoid IDS detection
**Example:** `nmap -T1 192.168.1.1`
**Use Case:** Stealth scanning with some speed

### `-T2` (Polite)
**Purpose:** Slows down to use less bandwidth
**Example:** `nmap -T2 192.168.1.1`
**Use Case:** Minimize network impact

### `-T3` (Normal)
**Purpose:** Default timing (equivalent to no -T option)
**Example:** `nmap -T3 192.168.1.1`
**Use Case:** Standard scanning

### `-T4` (Aggressive)
**Purpose:** Faster scan, assumes reliable network
**Example:** `nmap -T4 192.168.1.1`
**Use Case:** Fast scanning on reliable networks

### `-T5` (Insane)
**Purpose:** Very aggressive, may miss results
**Example:** `nmap -T5 192.168.1.1`
**Use Case:** Maximum speed, accuracy may suffer

### Fine-Grained Timing Control

### `--min-hostgroup`/`--max-hostgroup`
**Syntax:** `nmap --min-hostgroup <number> --max-hostgroup <number> <targets>`
**Purpose:** Controls parallel host scanning
**Example:** `nmap --min-hostgroup 10 --max-hostgroup 50 192.168.1.0/24`
**Use Case:** Optimizing scan performance

### `--min-parallelism`/`--max-parallelism`
**Syntax:** `nmap --min-parallelism <number> --max-parallelism <number> <targets>`
**Purpose:** Controls probe parallelization
**Example:** `nmap --min-parallelism 10 --max-parallelism 100 192.168.1.1`
**Use Case:** Tuning scan speed vs. accuracy

### `--min-rtt-timeout`/`--max-rtt-timeout`/`--initial-rtt-timeout`
**Syntax:** `nmap --min-rtt-timeout <time> --max-rtt-timeout <time> <targets>`
**Purpose:** Controls probe timeout
**Example:** `nmap --min-rtt-timeout 100ms --max-rtt-timeout 1000ms 192.168.1.1`
**Use Case:** Adjusting for network conditions

### `--max-retries`
**Syntax:** `nmap --max-retries <number> <targets>`
**Purpose:** Limits port scan probe retransmissions
**Example:** `nmap --max-retries 2 192.168.1.1`
**Use Case:** Speed up scans by limiting retries

### `--host-timeout`
**Syntax:** `nmap --host-timeout <time> <targets>`
**Purpose:** Give up on slow hosts
**Example:** `nmap --host-timeout 10m 192.168.1.0/24`
**Use Case:** Prevent hanging on unresponsive hosts

### `--scan-delay`/`--max-scan-delay`
**Syntax:** `nmap --scan-delay <time> --max-scan-delay <time> <targets>`
**Purpose:** Controls delay between probes
**Example:** `nmap --scan-delay 100ms --max-scan-delay 1s 192.168.1.1`
**Use Case:** Rate limiting to avoid IDS detection

### `--min-rate`/`--max-rate`
**Syntax:** `nmap --min-rate <number> --max-rate <number> <targets>`
**Purpose:** Controls packet sending rate
**Example:** `nmap --min-rate 100 --max-rate 1000 192.168.1.1`
**Use Case:** Precise control over scan speed

---

## Output Formats

Nmap supports various output formats for different analysis needs.

### Normal Output (Default)
**Syntax:** `nmap <targets>` or `nmap -oN <filename> <targets>`
**Purpose:** Human-readable output
**Example:** `nmap -oN scan_results.txt 192.168.1.1`
**Use Case:** Manual analysis, reporting

### `-oX` (XML Output)
**Syntax:** `nmap -oX <filename> <targets>`
**Purpose:** Structured XML output
**Example:** `nmap -oX scan_results.xml 192.168.1.1`
**Use Case:** Automated processing, integration with tools

### `-oS` (Script Kiddie Output)
**Syntax:** `nmap -oS <filename> <targets>`
**Purpose:** Leet speak output (mostly for fun)
**Example:** `nmap -oS l33t_results.txt 192.168.1.1`
**Use Case:** Entertainment, obfuscation

### `-oG` (Grepable Output)
**Syntax:** `nmap -oG <filename> <targets>`
**Purpose:** Grep-friendly format
**Example:** `nmap -oG scan_results.gnmap 192.168.1.1`
**Use Case:** Command-line processing with grep/awk

### `-oA` (All Formats)
**Syntax:** `nmap -oA <basename> <targets>`
**Purpose:** Saves in normal, XML, and grepable formats
**Example:** `nmap -oA comprehensive_scan 192.168.1.1`
**Use Case:** Maximum flexibility for later analysis

### Verbosity and Debugging

### `-v` (Verbose)
**Syntax:** `nmap -v <targets>`
**Purpose:** Increases verbosity level
**Example:** `nmap -v 192.168.1.1`
**Use Case:** Real-time progress monitoring

### `-vv` (Very Verbose)
**Syntax:** `nmap -vv <targets>`
**Purpose:** Even more verbose output
**Example:** `nmap -vv 192.168.1.1`
**Use Case:** Detailed progress information

### `-d` (Debug)
**Syntax:** `nmap -d <targets>`
**Purpose:** Enable debugging output
**Example:** `nmap -d 192.168.1.1`
**Use Case:** Troubleshooting scan issues

### `-dd` (Very Debug)
**Syntax:** `nmap -dd <targets>`
**Purpose:** More debugging output
**Example:** `nmap -dd 192.168.1.1`
**Use Case:** Deep troubleshooting

### `--reason`
**Syntax:** `nmap --reason <targets>`
**Purpose:** Display reason for port state
**Example:** `nmap --reason 192.168.1.1`
**Use Case:** Understanding why ports are in specific states

### `--stats-every`
**Syntax:** `nmap --stats-every <time> <targets>`
**Purpose:** Periodic status updates
**Example:** `nmap --stats-every 30s 192.168.1.0/24`
**Use Case:** Long-running scan monitoring

### `--packet-trace`
**Syntax:** `nmap --packet-trace <targets>`
**Purpose:** Show all packets sent and received
**Example:** `nmap --packet-trace 192.168.1.1`
**Use Case:** Deep network analysis

---

## NSE Scripting Engine

The Nmap Scripting Engine (NSE) provides advanced features through Lua scripts for vulnerability detection, backdoor detection, and more.

### `-sC` (Default Scripts)
**Syntax:** `nmap -sC <targets>`
**Purpose:** Runs default set of scripts
**Example:** `nmap -sC 192.168.1.1`
**Use Case:** Standard vulnerability and service enumeration

### `--script` (Specific Scripts)
**Syntax:** `nmap --script <script-name> <targets>`
**Purpose:** Run specific scripts
**Example:** `nmap --script vuln 192.168.1.1`
**Use Case:** Targeted vulnerability scanning

### Script Categories:
- **auth**: Authentication bypass
- **broadcast**: Network broadcast discovery
- **brute**: Brute force attacks
- **default**: Default scripts (-sC)
- **discovery**: Network discovery
- **dos**: Denial of service
- **exploit**: Exploitation scripts
- **external**: Scripts requiring external resources
- **fuzzer**: Fuzzing scripts
- **intrusive**: Intrusive scripts
- **malware**: Malware detection
- **safe**: Safe scripts unlikely to crash services
- **version**: Version detection enhancement
- **vuln**: Vulnerability detection

### Common Script Examples:

### Vulnerability Detection
```bash
# Run all vulnerability scripts
nmap --script vuln 192.168.1.1

# Specific vulnerability
nmap --script smb-vuln-ms17-010 192.168.1.1
```

### Service Enumeration
```bash
# HTTP enumeration
nmap --script http-enum 192.168.1.1 -p 80

# SMB enumeration
nmap --script smb-enum-shares 192.168.1.1 -p 445

# DNS enumeration
nmap --script dns-brute example.com
```

### Authentication Testing
```bash
# SSH brute force
nmap --script ssh-brute 192.168.1.1 -p 22

# HTTP authentication
nmap --script http-brute 192.168.1.1 -p 80
```

### `--script-args`
**Syntax:** `nmap --script <script> --script-args <args> <targets>`
**Purpose:** Pass arguments to scripts
**Example:** `nmap --script http-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1`
**Use Case:** Customizing script behavior

### `--script-updatedb`
**Syntax:** `nmap --script-updatedb`
**Purpose:** Update script database
**Example:** `nmap --script-updatedb`
**Use Case:** After installing new scripts

### `--script-trace`
**Syntax:** `nmap --script-trace --script <script> <targets>`
**Purpose:** Show script execution trace
**Example:** `nmap --script-trace --script vuln 192.168.1.1`
**Use Case:** Debugging script execution

---

## Firewall and IDS Evasion

These techniques help bypass security devices that might block or detect scans.

### `-f` (Fragment Packets)
**Syntax:** `nmap -f <targets>`
**Purpose:** Fragment TCP header over several packets
**Example:** `nmap -f 192.168.1.1`
**Use Case:** Bypassing packet filters

### `-ff` (Double Fragment)
**Syntax:** `nmap -ff <targets>`
**Purpose:** Fragment packets into 8-byte chunks
**Example:** `nmap -ff 192.168.1.1`
**Use Case:** More aggressive fragmentation

### `--mtu`
**Syntax:** `nmap --mtu <size> <targets>`
**Purpose:** Specify custom MTU for fragmentation
**Example:** `nmap --mtu 16 192.168.1.1`
**Use Case:** Custom fragmentation sizes

### `-D` (Decoy Scan)
**Syntax:** `nmap -D <decoy1>,<decoy2>,ME <targets>`
**Purpose:** Cloak scan among decoys
**Example:** `nmap -D 192.168.1.5,192.168.1.6,ME 192.168.1.1`
**Use Case:** Hide real source among fake IPs

### `-S` (Spoof Source Address)
**Syntax:** `nmap -S <spoofed-ip> <targets>`
**Purpose:** Spoof source IP address
**Example:** `nmap -S 192.168.1.100 192.168.1.1`
**Use Case:** IP address spoofing (requires special network access)

### `-e` (Use Interface)
**Syntax:** `nmap -e <interface> <targets>`
**Purpose:** Use specified network interface
**Example:** `nmap -e eth0 192.168.1.1`
**Use Case:** Control which interface sends packets

### `--source-port`
**Syntax:** `nmap --source-port <port> <targets>`
**Purpose:** Use specific source port
**Example:** `nmap --source-port 53 192.168.1.1`
**Use Case:** Bypass firewall rules based on source port

### `--proxies`
**Syntax:** `nmap --proxies <proxy-url> <targets>`
**Purpose:** Route through HTTP/SOCKS4 proxy chains
**Example:** `nmap --proxies http://proxy.example.com:8080 192.168.1.1`
**Use Case:** Scan through proxy servers

### `--data`
**Syntax:** `nmap --data <hex-string> <targets>`
**Purpose:** Append custom payload to packets
**Example:** `nmap --data 0xdeadbeef 192.168.1.1`
**Use Case:** Custom packet payloads

### `--data-string`
**Syntax:** `nmap --data-string <string> <targets>`
**Purpose:** Append custom ASCII string to packets
**Example:** `nmap --data-string "test" 192.168.1.1`
**Use Case:** Custom string payloads

### `--data-length`
**Syntax:** `nmap --data-length <number> <targets>`
**Purpose:** Append random data to packets
**Example:** `nmap --data-length 25 192.168.1.1`
**Use Case:** Padding packets to specific sizes

### `--ip-options`
**Syntax:** `nmap --ip-options <options> <targets>`
**Purpose:** Send packets with IP options
**Example:** `nmap --ip-options "S 192.168.1.1 192.168.1.2" 192.168.1.1`
**Use Case:** Source routing and other IP options

### `--ttl`
**Syntax:** `nmap --ttl <value> <targets>`
**Purpose:** Set IP time-to-live field
**Example:** `nmap --ttl 64 192.168.1.1`
**Use Case:** TTL manipulation for evasion

### `--randomize-hosts`
**Syntax:** `nmap --randomize-hosts <targets>`
**Purpose:** Randomize host scan order
**Example:** `nmap --randomize-hosts 192.168.1.0/24`
**Use Case:** Avoid pattern detection

### `--spoof-mac`
**Syntax:** `nmap --spoof-mac <mac-address> <targets>`
**Purpose:** Spoof MAC address
**Example:** `nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1`
**Use Case:** MAC address spoofing on local network

---

## Advanced Features

### IPv6 Support

### `-6` (IPv6 Scanning)
**Syntax:** `nmap -6 <IPv6-targets>`
**Purpose:** Enable IPv6 scanning
**Example:** `nmap -6 2001:db8::1`
**Use Case:** Scanning IPv6 networks

### Multiple Target Input

### `-iL` (Input from List)
**Syntax:** `nmap -iL <filename> [options]`
**Purpose:** Read target specification from file
**Example:** `nmap -iL targets.txt -sV`
**Use Case:** Large-scale scanning with predefined targets

### `-iR` (Random Targets)
**Syntax:** `nmap -iR <number> [options]`
**Purpose:** Scan random internet hosts
**Example:** `nmap -iR 100 -sn`
**Use Case:** Internet-wide research (use responsibly)

### `--exclude`
**Syntax:** `nmap --exclude <hosts> <targets>`
**Purpose:** Exclude specific hosts from scan
**Example:** `nmap --exclude 192.168.1.1,192.168.1.5 192.168.1.0/24`
**Use Case:** Avoiding critical systems during scans

### `--excludefile`
**Syntax:** `nmap --excludefile <filename> <targets>`
**Purpose:** Exclude hosts from file
**Example:** `nmap --excludefile exclude.txt 192.168.1.0/24`
**Use Case:** Maintaining permanent exclusion lists

### Resume and Continuation

### `--resume`
**Syntax:** `nmap --resume <filename>`
**Purpose:** Resume aborted scan from output file
**Example:** `nmap --resume scan_results.xml`
**Use Case:** Continuing interrupted large-scale scans

### Miscellaneous Options

### `--append-output`
**Syntax:** `nmap --append-output [options] <targets>`
**Purpose:** Append to output files instead of overwriting
**Example:** `nmap -oA scan --append-output 192.168.1.1`
**Use Case:** Adding results to existing scan files

### `--noninteractive`
**Syntax:** `nmap --noninteractive [options] <targets>`
**Purpose:** Disable runtime interaction
**Example:** `nmap --noninteractive 192.168.1.0/24`
**Use Case:** Automated scanning in scripts

### `--privileged`
**Syntax:** `nmap --privileged [options] <targets>`
**Purpose:** Assume user is privileged
**Example:** `nmap --privileged -sS 192.168.1.1`
**Use Case:** Force privileged mode

### `--unprivileged`
**Syntax:** `nmap --unprivileged [options] <targets>`
**Purpose:** Assume user is unprivileged
**Example:** `nmap --unprivileged 192.168.1.1`
**Use Case:** Force unprivileged mode

---

## Practical Examples and Common Combinations

### Quick Network Discovery
```bash
# Find live hosts on network
nmap -sn 192.168.1.0/24

# Fast scan of common ports
nmap -F 192.168.1.0/24

# Aggressive scan with OS detection
nmap -A 192.168.1.1
```

### Service Enumeration
```bash
# Comprehensive service detection
nmap -sV -sC -O 192.168.1.1

# Web server enumeration
nmap -p 80,443 --script http-enum,http-headers,http-methods 192.168.1.1

# SMB/NetBIOS enumeration
nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery 192.168.1.1
```

### Vulnerability Scanning
```bash
# General vulnerability scan
nmap --script vuln 192.168.1.1

# Specific vulnerability checks
nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067 192.168.1.1

# SSL/TLS vulnerability check
nmap --script ssl-enum-ciphers,ssl-heartbleed 192.168.1.1 -p 443
```

### Stealth and Evasion
```bash
# Slow, stealthy scan
nmap -T1 -f --randomize-hosts 192.168.1.0/24

# Decoy scan
nmap -D 192.168.1.5,192.168.1.6,ME 192.168.1.1

# Fragment packets and use specific source port
nmap -f --source-port 53 192.168.1.1
```

### Large Network Scanning
```bash
# Comprehensive network audit
nmap -sS -sV -O -A --top-ports 1000 -oA network_audit 192.168.0.0/16

# Fast discovery of entire Class B network
nmap -sn --min-hostgroup 256 --max-hostgroup 1024 10.0.0.0/16
```

---

## Legal Usage and Best Practices

### Legal Considerations

**CRITICAL: Only scan networks you own or have explicit written permission to test.**

### Legal Use Cases:
- **Your own networks**: Home networks, company networks you administer
- **Authorized penetration testing**: With written contracts and scope agreements
- **Bug bounty programs**: Following program rules and scope
- **Educational purposes**: On isolated lab networks or with permission

### Illegal Activities:
- Scanning networks without permission
- Port scanning ISP or cloud provider infrastructure without authorization
- Scanning government or military networks
- Using scans to facilitate attacks or unauthorized access
- Scanning to gather information for malicious purposes

### Best Practices

### 1. Authorization and Documentation
- Always obtain written permission before scanning
- Document scope, timing, and methods agreed upon
- Keep authorization letters and contracts
- Notify relevant stakeholders about planned scans

### 2. Scope Management
```bash
# Use exclude options for critical systems
nmap --exclude 192.168.1.1,192.168.1.50 192.168.1.0/24

# Create exclusion files for permanent restrictions
echo "192.168.1.1" > critical_systems.txt
echo "192.168.1.50" >> critical_systems.txt
nmap --excludefile critical_systems.txt 192.168.1.0/24
```

### 3. Timing and Impact Minimization
```bash
# Use polite timing for production networks
nmap -T2 --max-rate 100 192.168.1.0/24

# Scan during maintenance windows
nmap -T4 192.168.1.0/24  # Only during approved times
```

### 4. Monitoring and Logging
```bash
# Always save results for review
nmap -oA security_scan_$(date +%Y%m%d_%H%M%S) 192.168.1.0/24

# Use verbose mode to monitor progress
nmap -v -oN scan.log 192.168.1.0/24
```

### 5. Responsible Disclosure
- Report vulnerabilities found during authorized testing
- Follow responsible disclosure timelines
- Provide detailed, actionable reports
- Offer remediation assistance when appropriate

### 6. Technical Safety Measures

### Rate Limiting
```bash
# Limit scan rate to avoid overwhelming targets
nmap --max-rate 50 --scan-delay 100ms 192.168.1.0/24
```

### Host Timeouts
```bash
# Don't spend too long on unresponsive hosts
nmap --host-timeout 5m 192.168.1.0/24
```

### Exclude Critical Systems
```bash
# Always exclude critical infrastructure
nmap --exclude 192.168.1.10,192.168.1.20 192.168.1.0/24
```

### 7. Script Safety
```bash
# Use safe scripts for initial assessment
nmap --script safe 192.168.1.1

# Avoid potentially disruptive scripts in production
# These scripts can cause service disruption:
# - dos category scripts
# - brute force scripts without rate limiting
# - fuzzer scripts
# - intrusive scripts
```

### 8. Output Security
- Secure scan result files (contains sensitive network information)
- Use appropriate file permissions (600 or 640)
- Encrypt results files when storing long-term
- Delete temporary scan files after analysis

```bash
# Set secure permissions on output files
nmap -oA scan_results 192.168.1.1
chmod 600 scan_results.*
```

### 9. Network Etiquette
- Scan during off-peak hours when possible
- Use appropriate timing templates for the environment
- Monitor network impact during scans
- Stop scans if network performance is affected

### 10. Emergency Procedures
- Have contact information for network administrators
- Know how to quickly stop or pause scans
- Prepare incident response procedures
- Document any unintended impacts immediately

---

## Common Troubleshooting

### Scan Not Finding Hosts
```bash
# Try different host discovery methods
nmap -PS80,443,22 -PA80,443,22 192.168.1.0/24

# Skip host discovery if hosts are known to be up
nmap -Pn 192.168.1.1
```

### Slow Scans
```bash
# Use faster timing template
nmap -T4 192.168.1.1

# Reduce port range
nmap --top-ports 100 192.168.1.1

# Increase parallelism
nmap --min-parallelism 100 192.168.1.1
```

### Firewall Interference
```bash
# Try different scan types
nmap -sA 192.168.1.1  # ACK scan to map firewall rules
nmap -sF 192.168.1.1  # FIN scan
nmap -sN 192.168.1.1  # Null scan

# Use fragmentation
nmap -f 192.168.1.1
```

### Permission Issues
```bash
# Check if running as root for SYN scans
sudo nmap -sS 192.168.1.1

# Use connect scan if not root
nmap -sT 192.168.1.1
```

---
