# Volatility - Memory Forensics Framework

Advanced framework for memory dump analysis and digital forensics investigation.

## Installation

```bash
# Volatility 2.x
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install

# Volatility 3 (Python 3)
pip3 install volatility3

# Ubuntu/Debian
apt install volatility
```

## Basic Usage

```bash
# Image identification
volatility -f memory.dump imageinfo

# List running processes
volatility -f memory.dump --profile=Win7SP1x64 pslist

# Process tree view
volatility -f memory.dump --profile=Win7SP1x64 pstree

# Network connections
volatility -f memory.dump --profile=Win7SP1x64 netscan
```

## Process Analysis

```bash
# Process command lines
volatility -f memory.dump --profile=Win7SP1x64 cmdline

# DLL analysis
volatility -f memory.dump --profile=Win7SP1x64 dlllist -p 1234

# Process memory dump
volatility -f memory.dump --profile=Win7SP1x64 memdump -p 1234 -D output/

# Handle enumeration
volatility -f memory.dump --profile=Win7SP1x64 handles -p 1234
```

## Registry Analysis

```bash
# Registry hive list
volatility -f memory.dump --profile=Win7SP1x64 hivelist

# Registry key enumeration
volatility -f memory.dump --profile=Win7SP1x64 printkey -K "Software\Microsoft\Windows\CurrentVersion"

# Registry dump
volatility -f memory.dump --profile=Win7SP1x64 dumpregistry -D output/
```

## File System Analysis

```bash
# File scan
volatility -f memory.dump --profile=Win7SP1x64 filescan

# MFT parsing
volatility -f memory.dump --profile=Win7SP1x64 mftparser

# File extraction
volatility -f memory.dump --profile=Win7SP1x64 dumpfiles -Q 0x12345678 -D output/
```

## Malware Analysis

```bash
# Malware detection
volatility -f memory.dump --profile=Win7SP1x64 malfind

# Rootkit detection
volatility -f memory.dump --profile=Win7SP1x64 psxview

# Driver analysis
volatility -f memory.dump --profile=Win7SP1x64 driverscan

# Service enumeration
volatility -f memory.dump --profile=Win7SP1x64 svcscan
```

## Network Forensics

```bash
# Network connections (XP/2003)
volatility -f memory.dump --profile=WinXPSP3x86 connections

# Socket enumeration
volatility -f memory.dump --profile=WinXPSP3x86 sockets

# Network artifacts
volatility -f memory.dump --profile=Win7SP1x64 netscan
```

## Timeline Analysis

```bash
# Timeline creation
volatility -f memory.dump --profile=Win7SP1x64 timeliner --output=body > timeline.body

# Shellbags analysis
volatility -f memory.dump --profile=Win7SP1x64 shellbags

# USN journal
volatility -f memory.dump --profile=Win7SP1x64 mftparser --output=body
```

## Advanced Features

```bash
# Yara rule scanning
volatility -f memory.dump --profile=Win7SP1x64 yarascan -y rule.yar

# String extraction
strings memory.dump | volatility -f memory.dump --profile=Win7SP1x64 strings -s strings.txt

# Plugin development
volatility --plugins=custom_plugins -f memory.dump --profile=Win7SP1x64 customplugin
```

## Linux Memory Analysis

```bash
# Linux process list
volatility -f linux.mem --profile=LinuxUbuntu1404x64 linux_pslist

# Bash history
volatility -f linux.mem --profile=LinuxUbuntu1404x64 linux_bash

# Network status
volatility -f linux.mem --profile=LinuxUbuntu1404x64 linux_netstat
```

Comprehensive memory analysis framework supporting Windows, Linux, and Mac systems.
