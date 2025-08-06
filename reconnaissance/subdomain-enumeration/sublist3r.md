# Sublist3r - Fast Subdomains Enumeration Tool

Python-based tool that enumerates subdomains using OSINT techniques.

## Installation

```bash
# Clone repository
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt

# Install globally
sudo python setup.py install
```

## Basic Enumeration

```bash
# Basic scan
python sublist3r.py -d example.com

# Verbose output
python sublist3r.py -d example.com -v

# Save results
python sublist3r.py -d example.com -o results.txt

# Threading control
python sublist3r.py -d example.com -t 100
```

## Brute Force Mode

```bash
# Enable brute force
python sublist3r.py -d example.com -b

# Custom wordlist
python sublist3r.py -d example.com -b -w custom_wordlist.txt

# Specific search engines
python sublist3r.py -d example.com -e google,yahoo,virustotal
```

## Port Scanning Integration

```bash
# Scan common ports
python sublist3r.py -d example.com -p 80,443,22,21

# Custom port list
python sublist3r.py -d example.com -p 80,443,8080,8443,3000
```

## Search Engines

Supports multiple sources:
- Google
- Yahoo  
- Bing
- Baidu
- Ask
- Netcraft
- Virustotal
- ThreatCrowd
- DNSdumpster
- PassiveDNS

## Output Processing

```bash
# Remove duplicates
python sublist3r.py -d example.com | sort -u

# Check for live hosts
python sublist3r.py -d example.com | httpx -silent
```

## Limitations

Some sources may rate-limit requests during intensive scanning.
