# Hackers Tools Collection

A comprehensive collection of ethical hacking tools, penetration testing utilities, and cybersecurity resources organized by category.

## DISCLAIMER

This repository is for **EDUCATIONAL PURPOSES ONLY**. These tools should only be used on systems you own or have explicit permission to test. Unauthorized use of these tools on systems you don't own is illegal and unethical. The author is not responsible for any misuse of the information provided.


## Reconnaissance Tools

Information gathering and reconnaissance tools for the initial phase of penetration testing.

### Passive Reconnaissance
- **OSINT Tools**: Open Source Intelligence gathering
- **DNS Tools**: Domain name system enumeration
- **Subdomain Enumeration**: Finding subdomains and related assets

### Active Reconnaissance
- **Network Discovery**: Finding live hosts and services
- **Port Scanning**: Identifying open ports and services

## Scanning

Network and vulnerability scanning tools.

### Network Scanners
- **Nmap**: Network discovery and security auditing tool
- **Masscan**: High-speed port scanner
- **Zmap**: Internet-wide network scanner tool

### Vulnerability Scanners
- **OpenVAS**: Comprehensive vulnerability assessment
- **Nessus**: Professional vulnerability scanner
- **Nuclei**: Fast and customizable vulnerability scanner

### Web Scanners
- **Nikto**: Web server scanner
- **Dirb/Gobuster**: Directory and file enumeration
- **Wapiti**: Web application vulnerability scanner

## Enumeration Tools

Service enumeration and information extraction tools.

### Protocol-Specific Enumeration
- **SMB**: Server Message Block enumeration
- **SNMP**: Simple Network Management Protocol
- **LDAP**: Lightweight Directory Access Protocol
- **NFS**: Network File System
- **Database**: Various database enumeration tools

## Exploitation Tools

Tools for exploiting vulnerabilities and gaining access.

### Frameworks
- **Metasploit**: Comprehensive exploitation framework
- **Cobalt Strike**: Advanced threat emulation
- **Empire**: PowerShell post-exploitation agent

### Buffer Overflow
- **Pattern Creation**: Tools for creating unique patterns
- **Shellcode Generators**: Custom shellcode creation
- **Exploit Development**: Buffer overflow exploitation tools

## Web Application Testing Tools

Web application security testing tools.

### Directory Busting
- **Gobuster**: Fast directory/file enumeration
- **Dirbuster**: GUI-based directory bruteforcer
- **FFuF**: Fast web fuzzer

### SQL Injection
- **SQLMap**: Automatic SQL injection tool
- **SQLNinja**: SQL Server injection tool
- **NoSQLMap**: NoSQL injection tool

### Cross-Site Scripting (XSS)
- **XSStrike**: Advanced XSS detection suite
- **Xenotix**: XSS exploitation framework
- **BeEF**: Browser Exploitation Framework

### Proxies & Interceptors
- **Burp Suite**: Web application security testing platform
- **OWASP ZAP**: Web application security scanner
- **Mitmproxy**: Interactive HTTPS proxy

## Post-Exploitation Tools

Tools for maintaining access and moving laterally through networks.

### Privilege Escalation
- **LinEnum**: Linux enumeration script
- **WinPEAS**: Windows privilege escalation
- **GTFOBins**: Unix binaries for privilege escalation

### Persistence
- **Backdoor creation**: Various persistence mechanisms
- **Scheduled tasks**: Maintaining access through tasks
- **Registry modifications**: Windows registry persistence

### Lateral Movement
- **PsExec**: Remote command execution
- **WMI**: Windows Management Instrumentation
- **SSH tunneling**: Secure tunneling techniques

## Wireless Security

Wireless network security assessment tools.

### WiFi Security
- **Aircrack-ng**: WiFi security auditing suite
- **Reaver**: WPS attack tool
- **Wifite**: Automated wireless attack tool

### Bluetooth Security
- **BlueZ**: Bluetooth protocol stack
- **Btscanner**: Bluetooth device discovery
- **Spooftooph**: Bluetooth device spoofing

### RFID/NFC
- **Proxmark3**: RFID/NFC research platform
- **LibNFC**: Near Field Communication library
- **MFCUK**: Mifare Classic Universal toolkit

## Password Attacks

Password cracking and brute force tools.

### Hash Cracking
- **Hashcat**: Advanced password recovery
- **John the Ripper**: Password security auditing
- **RainbowCrack**: Rainbow table password cracker

### Online Attacks
- **Hydra**: Network logon cracker
- **Medusa**: Speedy, parallel password cracker
- **Patator**: Multi-purpose brute-forcer

### Wordlists
- **SecLists**: Security tester's companion
- **RockYou**: Popular password wordlist
- **Custom wordlists**: Domain-specific wordlists

## Forensics Tools

Digital forensics and incident response tools.

### Disk Analysis
- **Autopsy**: Digital forensics platform
- **Sleuth Kit**: File system analysis tools
- **PhotoRec**: File recovery software

### Memory Analysis
- **Volatility**: Memory forensics framework
- **Rekall**: Advanced memory analysis
- **LiME**: Linux Memory Extractor

### Network Forensics
- **Wireshark**: Network protocol analyzer
- **NetworkMiner**: Network forensic analysis tool
- **Tcpdump**: Command-line packet analyzer

## Reverse Engineering

Binary analysis and reverse engineering tools.

### Disassemblers
- **IDA Pro**: Interactive disassembler
- **Ghidra**: Software reverse engineering suite
- **Radare2**: Unix-like reverse engineering framework

### Debuggers
- **GDB**: GNU debugger
- **x64dbg**: Windows debugger
- **OllyDbg**: 32-bit assembler level debugger

### Hex Editors
- **HxD**: Freeware hex editor
- **Bless**: Full-featured hexadecimal editor
- **Hexedit**: Simple hex editor for Linux

## Cryptography Tools

Cryptographic tools and utilities.

### Encryption/Decryption
- **OpenSSL**: Cryptography toolkit
- **GPG**: GNU Privacy Guard
- **VeraCrypt**: Disk encryption software

### Steganography
- **Steghide**: Steganography program
- **StegSolve**: Steganography solver
- **Binwalk**: Firmware analysis tool

### SSL/TLS Analysis
- **SSLyze**: SSL configuration analyzer
- **testssl.sh**: SSL/TLS tester
- **SSLScan**: SSL cipher suite scanner

## Social Engineering Tools

Social engineering attack tools and frameworks.

### Phishing
- **SET**: Social Engineer Toolkit
- **Gophish**: Open-source phishing toolkit
- **King Phisher**: Phishing campaign toolkit

### Fake Access Points
- **Hostapd**: Access point daemon
- **Dnsmasq**: Lightweight DHCP/DNS server
- **Captive portals**: Fake login page generators

## Mobile Security

Mobile application and device security testing.

### Android Security
- **APKTool**: Reverse engineering Android APK files
- **MobSF**: Mobile security framework
- **Drozer**: Android security assessment framework

### iOS Security
- **Class-dump**: Objective-C class dumper
- **Clutch**: iOS application decrypter
- **iProxy**: iOS SSH tunnel

## Evasion Techniques

Anti-detection and evasion tools.

### Antivirus Evasion
- **Veil**: Payload generation framework
- **Shellter**: Dynamic shellcode injection tool
- **Phantom-Evasion**: AV evasion tool

### Firewall Evasion
- **Nmap evasion**: Stealth scanning techniques
- **Packet fragmentation**: Bypassing packet filters
- **Protocol tunneling**: Hiding traffic in legitimate protocols

## Malware Analysis Tools

Malware research and analysis tools.

### Static Analysis
- **PEiD**: PE identifier
- **Strings**: Extract text strings from binaries
- **File**: Determine file types

### Dynamic Analysis
- **Cuckoo Sandbox**: Automated malware analysis
- **REMnux**: Malware analysis toolkit
- **YARA**: Pattern matching engine

## Network Tools

Network manipulation and analysis utilities.

### Packet Sniffers
- **Wireshark**: Network protocol analyzer
- **Tcpdump**: Command-line packet analyzer
- **Ettercap**: Comprehensive network tool

### Spoofing Tools
- **Arpspoof**: ARP spoofing tool
- **DNSSpoof**: DNS spoofing tool
- **Macchanger**: MAC address changer

### Man-in-the-Middle
- **Bettercap**: Network attack and monitoring framework
- **MITMf**: Man-in-the-middle framework
- **SSLstrip**: SSL stripping proxy

## Cloud Security Tools

Cloud platform security assessment tools.

### AWS Security
- **ScoutSuite**: Cloud security auditing tool
- **Prowler**: AWS security best practices assessment
- **CloudMapper**: AWS visualization

### Azure Security
- **PowerZure**: Azure exploitation framework
- **MicroBurst**: Azure security assessment
- **Azure Security Center**: Built-in security management

### Container Security
- **Docker Bench**: Docker security benchmark
- **Clair**: Container vulnerability scanner
- **Anchore**: Container image inspection

## Utilities

General-purpose utilities and helper tools.

### Text Manipulation
- **CyberChef**: Data manipulation and analysis
- **Base64 tools**: Encoding/decoding utilities
- **Hash generators**: Various hashing algorithms

### Automation
- **Custom scripts**: Bash, Python, PowerShell scripts
- **Automation frameworks**: Task automation tools
- **CI/CD integration**: Continuous security testing

## Resources

Additional resources and reference materials.

### Wordlists
- **Common passwords**: Frequently used passwords
- **Usernames**: Common username lists
- **Directories**: Web directory wordlists

### Payloads
- **Web shells**: PHP, ASP, JSP shells
- **Reverse shells**: Various reverse shell payloads
- **XSS payloads**: Cross-site scripting vectors

### Documentation
- **Cheat sheets**: Quick reference guides
- **Methodologies**: Penetration testing methodologies
- **Best practices**: Security testing guidelines

## Contributing

Contributions are welcome! Please read the contribution guidelines before submitting pull requests.

1. Fork the repository
2. Create a feature branch
3. Add your tool/resource with proper documentation
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/stilla1ex/hackers-tools/blob/main/LICENSE) file for details.

## Contact

For questions, suggestions, or collaborations, please open an issue on GitHub.

---

**Remember**: Always use tools responsibly and only on systems you own or have explicit permission to test. Happy hacking!
