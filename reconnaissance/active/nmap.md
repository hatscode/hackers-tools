# Nmap (Network Mapper)

Nmap is a powerful open-source tool for network discovery and security auditing. It can be used to discover hosts, services, operating systems, and vulnerabilities on a network.

## Practical Command Examples

### Scanning a Single Host

```bash
nmap -sV -O -p- 192.168.1.100  # -sV: Service version detection, -O: OS detection, -p-: Scan all ports (1-65535)
```

This command performs a comprehensive scan on a single IP address, detecting services, versions, and the operating system.

### Scanning a Subnet

```bash
nmap -sn 192.168.1.0/24  # -sn: Ping scan (no port scan), scans the entire subnet for live hosts
```

Use this to discover all active hosts on a subnet without scanning ports, which is faster for network mapping.

### Service and Version Detection

```bash
nmap -sV -sC -A 192.168.1.100  # -sV: Service version detection, -sC: Run default scripts, -A: Aggressive scan (OS detection, version detection, script scanning, traceroute)
```

This aggressive scan provides detailed information about services, versions, and potential vulnerabilities using Nmap's scripting engine.

### Additional Useful Options

- `-T4`: Timing template (0-5, higher is faster but more detectable)
- `--script=vuln`: Run vulnerability detection scripts
- `-oN output.txt`: Save results to a file in normal format
- `-v`: Verbose output for more details

### Example with Timing and Output

```bash
nmap -T4 -sV -p 80,443 --script=http-title 192.168.1.0/24 -oN scan_results.txt  # -T4: Aggressive timing, -sV: Version detection, -p: Specific ports, --script: Run specific script, -oN: Output to file
```

This scans for web servers on ports 80 and 443 across the subnet, runs a script to grab page titles, and saves the output.
