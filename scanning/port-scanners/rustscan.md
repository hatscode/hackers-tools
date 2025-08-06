# RustScan - Fast Port Scanner

Modern port scanner written in Rust with adaptive learning capabilities.

## Installation

```bash
# Download binary
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb

# Using cargo
cargo install rustscan

# Docker
docker pull rustscan/rustscan
```

## Quick Start

```bash
# Basic scan
rustscan -a 192.168.1.1

# Custom port range
rustscan -a 192.168.1.1 -r 1-1000

# Multiple targets
rustscan -a 192.168.1.1,192.168.1.2

# CIDR notation
rustscan -a 192.168.1.0/24
```

## Performance Options

```bash
# Batch size adjustment
rustscan -a 192.168.1.1 -b 1000

# Timeout control
rustscan -a 192.168.1.1 -t 500

# Thread count
rustscan -a 192.168.1.1 --ulimit 10000
```

## Nmap Integration

```bash
# Pass results to nmap
rustscan -a 192.168.1.1 -- -A -sC

# Custom nmap arguments
rustscan -a 192.168.1.1 -- -sV -O --script vuln
```

## Configuration

```toml
# ~/.rustscan.toml
[default]
batch_size = 4500
timeout = 1500
ulimit = 5000
```

## Output Formats

Supports JSON, XML, and standard text output formats.
