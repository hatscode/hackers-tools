# GDB - GNU Debugger

Powerful debugger for C, C++, and other programming languages.

## Installation

```bash
# Ubuntu/Debian
apt install gdb

# Enhanced GDB with additional features
apt install gdb-multiarch
```

## Basic Commands

```bash
# Start debugging
gdb ./program
gdb --args ./program arg1 arg2

# Load core dump
gdb ./program core

# Attach to running process
gdb -p PID
```

## Execution Control

```bash
# Set breakpoints
break main
break file.c:100
break function_name

# Run program
run
run arg1 arg2

# Continue execution
continue
c

# Step execution
step    # Step into functions
next    # Step over functions
finish  # Step out of current function
```

## Memory Examination

```bash
# Examine memory
x/10i $rip      # 10 instructions at RIP
x/20x $rsp      # 20 hex values at stack pointer
x/s 0x400000    # String at address

# Print variables
print variable
print $rax
print *(int*)0x400000

# Display expressions
display $rip
display variable
```

## Register Operations

```bash
# Show registers
info registers
info registers rax rbx

# Modify registers
set $rax = 0x41414141
```

## Stack Analysis

```bash
# Show stack trace
backtrace
bt

# Navigate stack frames
frame 0
up
down
```

## Advanced Features

```bash
# Disassembly
disassemble main
disassemble /r main

# Search memory
find 0x400000, +1000, "string"

# Python scripting
python print("Hello from GDB")
```

## GDB Extensions

Popular extensions:
- PEDA (Python Exploit Development Assistance)
- GEF (GDB Enhanced Features)
- pwndbg (Exploit development)
