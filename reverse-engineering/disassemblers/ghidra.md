# Ghidra - Software Reverse Engineering Suite

NSA-developed reverse engineering framework for analyzing compiled code.

## Installation

```bash
# Download from NSA GitHub releases
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
unzip ghidra_10.4_PUBLIC_20230928.zip

# Start Ghidra
./ghidra_10.4_PUBLIC/ghidraRun
```

## Project Management

### Creating Projects
- Non-shared projects for individual analysis
- Shared projects for team collaboration
- Version control integration

### Importing Files
- Executable file import wizard
- Batch import capabilities
- Various file format support

## Code Analysis Features

### Auto Analysis
Ghidra performs automatic analysis including:
- Function identification
- String analysis
- Symbol resolution
- Cross-reference generation

### Manual Analysis
- Function signature editing
- Variable renaming
- Comment addition
- Custom data type creation

## Interface Components

### CodeBrowser
Primary analysis interface showing:
- Disassembly listing
- Decompiled C code
- Program tree
- Symbol table

### Decompiler
High-level C-like code generation from assembly:
- Variable type inference
- Control flow reconstruction
- Function parameter identification

## Scripting Capabilities

### Built-in Scripts
Hundreds of analysis scripts for:
- Malware analysis
- Vulnerability research
- Code auditing
- Binary diffing

### Custom Script Development
- Java scripting environment
- Python script support
- Ghidra API access

## Advanced Features

### Binary Diffing
- Version comparison capabilities
- Patch analysis
- Code change identification

### Processor Support
- x86/x64 architecture
- ARM processors
- MIPS architecture  
- PowerPC support
- Custom processor definitions

## Collaboration Tools

- Multi-user project sharing
- Change tracking
- Merge conflict resolution
- Export/import capabilities

## Extensions and Plugins

Active community developing:
- Additional processor modules
- Analysis enhancement plugins
- Integration tools
- Custom analyzers
