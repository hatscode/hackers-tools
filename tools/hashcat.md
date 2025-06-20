# The Complete Guide to Mastering Hashcat

## Table of Contents
1. [Introduction to Hashcat](#introduction-to-hashcat)
2. [Installation and Setup](#installation-and-setup)
3. [Understanding Hash Types](#understanding-hash-types)
4. [Attack Modes Deep Dive](#attack-modes-deep-dive)
5. [Practical Cracking Techniques](#practical-cracking-techniques)
6. [Optimizing Performance](#optimizing-performance)
7. [Advanced Features](#advanced-features)
8. [Ethical Considerations](#ethical-considerations)
9. [Troubleshooting](#troubleshooting)
10. [Conclusion](#conclusion)

## Introduction to Hashcat

Hashcat is the world's fastest and most advanced password recovery tool, supporting:
- Five unique attack modes
- Over 300 highly-optimized hashing algorithms
- Multi-OS support (Linux, Windows, macOS)
- Multi-platform support (CPU, GPU, APU, etc.)

Originally developed as proprietary software, Hashcat was open-sourced in 2015 and has since become the industry standard for password cracking.

## Installation and Setup

### Kali Linux Installation
```bash
sudo apt update && sudo apt install hashcat
```

### Windows Installation
1. Download from [hashcat.net](https://hashcat.net/hashcat/)
2. Extract the ZIP file
3. Add to system PATH

### Verifying Installation
```bash
hashcat --version
```

### GPU Drivers Setup
For optimal performance, ensure proper GPU drivers are installed:
- NVIDIA: Install CUDA toolkit
- AMD: Install ROCm or OpenCL drivers
- Intel: Install OpenCL runtime

## Understanding Hash Types

Hashcat supports hundreds of hash algorithms. Key categories include:

### Common Hash Types
| Hash Type      | Mode | Example                              |
|----------------|------|--------------------------------------|
| MD5            | 0    | 8743b52063cd84097a65d1633f5c74f5     |
| SHA1           | 100  | b89eaac7e61417341b710b727768294d0e6a277b |
| SHA256         | 1400 | 127e6fbfe24a750e72930c220a8e138275656b8e |
| NTLM           | 1000 | b4b9b02e6f09a9bd760f388b67351e2b     |
| bcrypt         | 3200 | $2a$05$LhL2SzbPvSjPwll2lknTx.8YJz5 |

### Identifying Hashes
Use `hashid` or online tools:
```bash
hashid -m '8743b52063cd84097a65d1633f5c74f5'
```

## Attack Modes Deep Dive

### 1. Dictionary Attack (-a 0)
Most common attack using wordlists:
```bash
hashcat -a 0 -m 0 target_hashes.txt /path/to/wordlist.txt
```

### 2. Combinator Attack (-a 1)
Combines words from two wordlists:
```bash
hashcat -a 1 -m 0 target_hashes.txt wordlist1.txt wordlist2.txt
```

### 3. Mask Attack (-a 3)
Brute-force with pattern:
```bash
hashcat -a 3 -m 0 target_hashes.txt ?u?l?l?l?d?d?s
```

### 4. Hybrid Attack (-a 6 and -a 7)
Combine dictionary and mask:
```bash
hashcat -a 6 -m 0 target_hashes.txt wordlist.txt ?d?d?d
```

### 5. Rule-Based Attack
Advanced word mutation:
```bash
hashcat -a 0 -m 0 target_hashes.txt wordlist.txt -r rules/best64.rule
```

## Practical Cracking Techniques

### Basic Workflow
1. Collect hashes
2. Identify hash type
3. Select appropriate attack mode
4. Execute attack
5. Analyze results

### Example: Cracking Windows NTLM Hashes
```bash
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt -O -w 3
```

### Example: Cracking WordPress Hashes
```bash
hashcat -a 0 -m 400 wordpress_hashes.txt rockyou.txt
```

### Using Potfile
View previously cracked hashes:
```bash
hashcat --show
```

## Optimizing Performance

### Performance Tweaks
1. **Workload Profiles**: -w 1 (low) to -w 4 (insane)
2. **Optimization Flags**: -O (optimized kernels)
3. **GPU Settings**: --force or --hwmon-temp-abort

### Benchmarking
```bash
hashcat -b
```

## Advanced Features

### Distributed Cracking
```bash
hashcat --brain-server
hashcat --brain-client
```

### Custom Rules
Create your own rule files:
```
:
l
u
c
s
```

### Hashcat Utils
Additional tools for:
- Wordlist manipulation
- Rule generation
- Mask analysis

## Ethical Considerations

### Legal Compliance
- Always obtain proper authorization
- Follow local laws and regulations
- Respect privacy and data protection laws

### Responsible Disclosure
When finding vulnerabilities:
1. Document findings
2. Notify affected parties
3. Allow reasonable time for fixes
4. Publish details responsibly

## Troubleshooting

### Common Issues
1. **Driver Problems**: Ensure proper GPU drivers
2. **Hash Format**: Verify correct hash format
3. **Memory Limits**: Adjust --gpu-memlimit
4. **Temperature**: Monitor with --hwmon-temp-abort

### Debugging
```bash
hashcat -I  # Show device info
hashcat -V  # Verbose output
```

## Conclusion

Hashcat is an incredibly powerful tool that every security professional should master. By understanding its various attack modes, optimization techniques, and practical applications, you can significantly improve your password security testing capabilities.

### Next Steps
1. Practice with different hash types
2. Experiment with custom rules
3. Join the Hashcat community
4. Stay updated with new releases

Remember: With great power comes great responsibility. Always use Hashcat ethically and legally.

## Additional Resources
- [Official Hashcat Wiki](https://hashcat.net/wiki/)
- [Hashcat Forum](https://hashcat.net/forum/)
- [Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Wordlists Repository](https://weakpass.com/wordlist)
