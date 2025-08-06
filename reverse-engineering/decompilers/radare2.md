# Radare2 - Reverse Engineering Framework

Open-source reverse engineering framework with advanced static and dynamic analysis capabilities for multiple architectures and file formats.

## Installation

```bash
# Ubuntu/Debian/Kali
apt install radare2

# From source (latest version)
git clone https://github.com/radareorg/radare2.git
cd radare2
sys/install.sh

# Package managers
# macOS with Homebrew
brew install radare2

# Windows
# Download from https://github.com/radareorg/radare2/releases

# Docker
docker run -it radare/radare2
```

## Core Components

### Main Tools
- **r2** - Core reverse engineering tool
- **rabin2** - Binary information extractor
- **rasm2** - Assembler and disassembler
- **rahash2** - Hashing and checksums
- **radiff2** - Binary diffing tool
- **rax2** - Number format converter
- **ragg2** - Code generator and compiler

## Basic Usage and Navigation

### Opening Files
```bash
# Open file in read-only mode
r2 /path/to/binary

# Open with write permissions
r2 -w /path/to/binary

# Open at specific address
r2 -B 0x08048000 /path/to/binary

# Open with architecture specification
r2 -a x86 -b 32 /path/to/binary

# Debug mode
r2 -d /path/to/binary
```

### Basic Commands
```bash
# Analysis commands
[0x08048000]> aa      # Auto analysis
[0x08048000]> aaa     # More thorough analysis
[0x08048000]> aaaa    # Even more analysis

# Information commands
[0x08048000]> i       # File information
[0x08048000]> ii      # Imports
[0x08048000]> ie      # Entrypoints
[0x08048000]> iz      # Strings in data section
[0x08048000]> izz     # All strings

# Navigation
[0x08048000]> s main  # Seek to main function
[0x08048000]> s 0x401000  # Seek to address
[0x08048000]> s+10    # Move forward 10 bytes
[0x08048000]> s-5     # Move backward 5 bytes
```

### Disassembly and Analysis
```bash
# Disassembly
[0x08048000]> pd       # Print disassembly
[0x08048000]> pd 20    # Print 20 instructions
[0x08048000]> pdf      # Print disassembly of function
[0x08048000]> pdc      # Print decompiled C-like code

# Function analysis
[0x08048000]> afl      # List functions
[0x08048000]> afi      # Function info
[0x08048000]> afvs     # Function variables
[0x08048000]> afn newname  # Rename function

# Cross-references
[0x08048000]> axt      # References to current address
[0x08048000]> axf      # References from current address
```

## Advanced Analysis Features

### Function Analysis
```bash
# Function detection and analysis
[0x08048000]> af       # Analyze function
[0x08048000]> afc      # Calculate function cyclomatic complexity
[0x08048000]> afC      # Function calling convention
[0x08048000]> afr      # Function recursion detection

# Function signatures
[0x08048000]> afs      # Function signature
[0x08048000]> afsr     # Function signature recognition

# Function visualization
[0x08048000]> VV       # Visual function graph
[0x08048000]> agC      # Function call graph
```

### Data Analysis
```bash
# Data types and structures
[0x08048000]> td       # List data types
[0x08048000]> ts       # List structures
[0x08048000]> ta       # Analyze data references

# String analysis
[0x08048000]> /        # Search
[0x08048000]> / hello  # Search for "hello"
[0x08048000]> /x 41424344  # Search for hex bytes
[0x08048000]> /r       # Search for ROP gadgets

# Memory maps
[0x08048000]> dm       # Memory maps
[0x08048000]> dmi      # Memory information
```

## Visual Mode

### Basic Visual Navigation
```bash
# Enter visual mode
[0x08048000]> V

# Visual mode commands (while in visual mode):
# hjkl or arrow keys - Navigate
# Enter - Follow jumps/calls  
# u - Go back
# . - Seek to program counter
# / - Search
# : - Command prompt
# q - Quit visual mode
```

### Visual Graph Mode
```bash
# Enter visual graph mode
[0x08048000]> VV

# Graph mode navigation:
# hjkl - Navigate nodes
# tab - Switch between nodes
# R - Randomize colors
# r - Refresh graph
# + - Zoom in
# - - Zoom out
```

## Scripting and Automation

### R2pipe Scripting (Python)
```python
#!/usr/bin/env python3
import r2pipe

def analyze_binary(binary_path):
    # Open binary with r2pipe
    r2 = r2pipe.open(binary_path)
    
    # Initial analysis
    r2.cmd('aa')
    
    # Get basic information
    info = r2.cmdj('ij')  # JSON output
    print(f"Architecture: {info['bin']['arch']}")
    print(f"Bits: {info['bin']['bits']}")
    print(f"Endian: {info['bin']['endian']}")
    
    # List functions
    functions = r2.cmdj('aflj')
    print(f"\nFound {len(functions)} functions:")
    
    for func in functions:
        print(f"  {func['name']} @ 0x{func['offset']:x}")
    
    # Find dangerous functions
    dangerous_functions = ['strcpy', 'sprintf', 'gets', 'scanf']
    imports = r2.cmdj('iij')
    
    print("\nDangerous imports found:")
    for imp in imports:
        if any(danger in imp['name'] for danger in dangerous_functions):
            print(f"  {imp['name']} @ 0x{imp['plt']:x}")
    
    # Analyze strings
    strings = r2.cmdj('izzj')
    suspicious_strings = []
    
    for string in strings:
        content = string['string']
        if any(keyword in content.lower() for keyword in 
               ['password', 'admin', 'secret', 'key']):
            suspicious_strings.append(string)
    
    if suspicious_strings:
        print("\nSuspicious strings found:")
        for s in suspicious_strings:
            print(f"  '{s['string']}' @ 0x{s['vaddr']:x}")
    
    r2.quit()

# Usage
if __name__ == "__main__":
    analyze_binary("/path/to/binary")
```

### Advanced Automation Script
```python
#!/usr/bin/env python3
import r2pipe
import json

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.r2 = r2pipe.open(binary_path)
        self.r2.cmd('aaa')  # Thorough analysis
        
    def find_vulnerabilities(self):
        """Find potential vulnerabilities"""
        vulnerabilities = []
        
        # Check for dangerous function calls
        dangerous_funcs = {
            'strcpy': 'Buffer overflow risk',
            'sprintf': 'Format string vulnerability', 
            'gets': 'Buffer overflow risk',
            'scanf': 'Input validation issue'
        }
        
        for func_name, risk in dangerous_funcs.items():
            # Search for function calls
            results = self.r2.cmd(f'/c {func_name}').strip().split('\n')
            
            for result in results:
                if result and 'call' in result.lower():
                    addr = result.split()[0]
                    vulnerabilities.append({
                        'type': risk,
                        'function': func_name,
                        'address': addr,
                        'description': f'Call to {func_name} at {addr}'
                    })
        
        return vulnerabilities
    
    def analyze_crypto(self):
        """Detect cryptographic constants"""
        crypto_constants = {
            0x67452301: 'MD5 constant',
            0x5A827999: 'SHA-1 constant',
            0x428A2F98: 'SHA-256 constant'
        }
        
        found_constants = []
        
        for constant, description in crypto_constants.items():
            # Search for hex constant
            hex_const = f"{constant:08x}"
            results = self.r2.cmd(f'/x {hex_const}').strip().split('\n')
            
            for result in results:
                if result:
                    addr = result.split()[0]
                    found_constants.append({
                        'constant': f'0x{constant:08x}',
                        'description': description,
                        'address': addr
                    })
        
        return found_constants
    
    def extract_strings(self):
        """Extract and categorize interesting strings"""
        strings = self.r2.cmdj('izzj')
        
        categorized = {
            'urls': [],
            'paths': [],
            'credentials': [],
            'crypto': [],
            'suspicious': []
        }
        
        for string in strings:
            content = string['string'].lower()
            
            if 'http' in content or 'ftp' in content:
                categorized['urls'].append(string)
            elif '/' in content and len(content) > 5:
                categorized['paths'].append(string)
            elif any(word in content for word in ['password', 'pass', 'pwd', 'secret']):
                categorized['credentials'].append(string)
            elif any(word in content for word in ['aes', 'rsa', 'des', 'key', 'cipher']):
                categorized['crypto'].append(string)
            elif any(word in content for word in ['admin', 'root', 'debug', 'test']):
                categorized['suspicious'].append(string)
        
        return categorized
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        report = {
            'file_info': self.r2.cmdj('ij'),
            'functions': self.r2.cmdj('aflj'),
            'imports': self.r2.cmdj('iij'),
            'exports': self.r2.cmdj('iEj'),
            'vulnerabilities': self.find_vulnerabilities(),
            'crypto_constants': self.analyze_crypto(),
            'strings': self.extract_strings()
        }
        
        return report
    
    def close(self):
        self.r2.quit()

# Usage example
if __name__ == "__main__":
    analyzer = BinaryAnalyzer("/path/to/malware.exe")
    
    report = analyzer.generate_report()
    
    # Print summary
    print(f"Binary: {report['file_info']['core']['file']}")
    print(f"Architecture: {report['file_info']['bin']['arch']}")
    print(f"Functions: {len(report['functions'])}")
    print(f"Imports: {len(report['imports'])}")
    print(f"Vulnerabilities: {len(report['vulnerabilities'])}")
    
    # Save detailed report
    with open('analysis_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    analyzer.close()
```

## Debugging and Dynamic Analysis

### Basic Debugging
```bash
# Start debugging session
r2 -d /path/to/binary

# Debug commands
[0x08048000]> db main    # Set breakpoint at main
[0x08048000]> dc         # Continue execution
[0x08048000]> ds         # Step instruction
[0x08048000]> dso        # Step over
[0x08048000]> dr         # Show registers
[0x08048000]> dm         # Memory maps
[0x08048000]> px 64      # Print 64 bytes in hex
```

### Memory Analysis
```bash
# Memory operations
[0x08048000]> px @ esp   # Print memory at ESP
[0x08048000]> pxw @ esp  # Print words at ESP
[0x08048000]> ps @ 0x401000  # Print string at address

# Memory modification
[0x08048000]> wx 9090    # Write NOP instructions
[0x08048000]> wa nop     # Write assembly instruction
```

## Binary Patching

### Manual Patching
```bash
# Open in write mode
r2 -w /path/to/binary

# Patch instructions
[0x08048000]> s 0x401000
[0x08048000]> wa "nop; nop"  # Replace with NOPs
[0x08048000]> wx 9090        # Write hex bytes directly

# Save changes
[0x08048000]> wc             # Write changes to file
```

### Automated Patching Script
```python
#!/usr/bin/env python3
import r2pipe

def patch_binary(binary_path, patches):
    """Apply patches to binary"""
    r2 = r2pipe.open(binary_path, flags=['-w'])  # Write mode
    
    for patch in patches:
        address = patch['address']
        new_code = patch['code']
        description = patch.get('description', 'Patch')
        
        print(f"Applying patch: {description}")
        print(f"  Address: 0x{address:x}")
        print(f"  New code: {new_code}")
        
        # Seek to address and apply patch
        r2.cmd(f's 0x{address:x}')
        r2.cmd(f'wa {new_code}')
    
    # Save changes
    r2.cmd('wc')
    r2.quit()
    
    print("Patches applied successfully")

# Example patches
patches = [
    {
        'address': 0x401000,
        'code': 'mov eax, 1; ret',
        'description': 'Always return true'
    },
    {
        'address': 0x401020,
        'code': 'nop; nop; nop',
        'description': 'Remove security check'
    }
]

patch_binary('/path/to/binary', patches)
```

## Malware Analysis

### Comprehensive Malware Analysis
```python
#!/usr/bin/env python3
import r2pipe
import hashlib
import requests

class MalwareAnalyzer:
    def __init__(self, sample_path):
        self.r2 = r2pipe.open(sample_path)
        self.sample_path = sample_path
        self.r2.cmd('aaa')
    
    def basic_info(self):
        """Extract basic malware information"""
        info = self.r2.cmdj('ij')
        
        # Calculate hashes
        with open(self.sample_path, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
        
        return {
            'filename': info['core']['file'],
            'filesize': info['core']['size'],
            'md5': md5_hash,
            'sha256': sha256_hash,
            'architecture': info['bin']['arch'],
            'bits': info['bin']['bits'],
            'type': info['bin']['class']
        }
    
    def find_network_indicators(self):
        """Find network-related indicators"""
        indicators = []
        
        # Search for IP addresses
        ip_results = self.r2.cmd('/R [0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}')
        
        # Search for URLs
        url_results = self.r2.cmd('/R https?://[^\\s]+')
        
        # Search for domain names
        domain_results = self.r2.cmd('/R [a-zA-Z0-9.-]+\\.(com|org|net|exe|dll)')
        
        # Parse results and add to indicators
        for result in [ip_results, url_results, domain_results]:
            if result.strip():
                indicators.extend(result.strip().split('\\n'))
        
        return list(set(indicators))  # Remove duplicates
    
    def find_persistence_mechanisms(self):
        """Identify persistence mechanisms"""
        persistence_indicators = [
            'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'SYSTEM\\\\CurrentControlSet\\\\Services',
            'schtasks',
            'at.exe',
            'wscript',
            'cscript'
        ]
        
        found_indicators = []
        
        for indicator in persistence_indicators:
            results = self.r2.cmd(f'/ {indicator}')
            if results.strip():
                found_indicators.append({
                    'type': 'persistence',
                    'indicator': indicator,
                    'locations': results.strip().split('\\n')
                })
        
        return found_indicators
    
    def analyze_anti_analysis(self):
        """Detect anti-analysis techniques"""
        anti_analysis_indicators = [
            'IsDebuggerPresent',
            'CheckRemoteDebuggerPresent',
            'FindWindow',
            'GetTickCount',
            'Sleep',
            'VirtualProtect'
        ]
        
        found_techniques = []
        
        for indicator in anti_analysis_indicators:
            # Check imports
            imports = self.r2.cmdj('iij')
            for imp in imports:
                if indicator.lower() in imp['name'].lower():
                    found_techniques.append({
                        'technique': 'api_check',
                        'api': imp['name'],
                        'address': f"0x{imp['plt']:x}"
                    })
        
        return found_techniques
    
    def generate_yara_rule(self, rule_name):
        """Generate basic YARA rule for the sample"""
        info = self.basic_info()
        strings = self.r2.cmdj('izzj')
        
        # Select unique strings for YARA rule
        unique_strings = []
        for string in strings[:10]:  # Limit to first 10 strings
            if len(string['string']) > 8 and string['string'].isprintable():
                unique_strings.append(string['string'])
        
        yara_rule = f'''
rule {rule_name} {{
    meta:
        description = "Auto-generated rule for {info['filename']}"
        hash_md5 = "{info['md5']}"
        hash_sha256 = "{info['sha256']}"
        
    strings:
'''
        
        for i, string in enumerate(unique_strings):
            yara_rule += f'        $s{i} = "{string}"\n'
        
        yara_rule += '''
    condition:
        uint16(0) == 0x5A4D and  // PE signature
        3 of ($s*)
}
'''
        
        return yara_rule
    
    def full_analysis(self):
        """Perform comprehensive malware analysis"""
        analysis_report = {
            'basic_info': self.basic_info(),
            'functions': len(self.r2.cmdj('aflj')),
            'imports': self.r2.cmdj('iij'),
            'strings': self.r2.cmdj('izzj'),
            'network_indicators': self.find_network_indicators(),
            'persistence': self.find_persistence_mechanisms(),
            'anti_analysis': self.analyze_anti_analysis(),
            'yara_rule': self.generate_yara_rule('AutoGenerated_Rule')
        }
        
        return analysis_report
    
    def close(self):
        self.r2.quit()

# Usage
if __name__ == "__main__":
    analyzer = MalwareAnalyzer("/path/to/malware.exe")
    report = analyzer.full_analysis()
    
    print("=== Malware Analysis Report ===")
    print(f"File: {report['basic_info']['filename']}")
    print(f"MD5: {report['basic_info']['md5']}")
    print(f"SHA256: {report['basic_info']['sha256']}")
    print(f"Functions: {report['functions']}")
    print(f"Network Indicators: {len(report['network_indicators'])}")
    print(f"Persistence Mechanisms: {len(report['persistence'])}")
    print(f"Anti-Analysis Techniques: {len(report['anti_analysis'])}")
    
    # Save YARA rule
    with open(f"{report['basic_info']['filename']}.yar", 'w') as f:
        f.write(report['yara_rule'])
    
    analyzer.close()
```

Powerful and flexible reverse engineering framework excellent for binary analysis, malware research, and exploit development across multiple platforms.
