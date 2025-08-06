# x64dbg - Windows x64/x32 Debugger

Open-source user-mode debugger for Windows with modern interface and advanced reverse engineering capabilities.

## Installation

```bash
# Download from official website
# https://x64dbg.com/

# Windows installation
1. Download x64dbg release
2. Extract to desired directory
3. Run x96dbg.exe (launcher for both x32 and x64)

# Portable version available
# No installation required, run directly from folder

# Plugin ecosystem
# Plugins available from: https://github.com/x64dbg/x64dbg/wiki/Plugins
```

## Interface Overview

### Main Windows
- **CPU View**: Assembly instructions, registers, stack, memory
- **Memory Map**: Process memory regions and permissions
- **Call Stack**: Function call hierarchy
- **Threads**: Process threads information
- **Handles**: System handles (files, registry, etc.)
- **Symbols**: Loaded symbols and functions
- **References**: String references and constants

### Toolbar Components
- **File Operations**: Open, attach, detach
- **Execution Control**: Run, pause, step, restart
- **Breakpoints**: Set, toggle, manage breakpoints
- **Analysis**: Static analysis and code analysis
- **Plugins**: Access to installed plugins

## Basic Debugging Operations

### Loading and Attaching
```
# Load executable
File → Open → Select executable
Configure command line arguments and working directory

# Attach to running process
File → Attach → Select process from list
Choose appropriate architecture (x32/x64)

# Debug child processes
Options → Preferences → Events → Break on Process Creation
```

### Execution Control
```
# Basic execution commands
F9 - Run/Continue
F7 - Step Into
F8 - Step Over
Ctrl+F7 - Step Into (skip system calls)
Ctrl+F8 - Step Over (skip system calls)
F4 - Run to Selection
Alt+F9 - Execute until return

# Advanced execution
Ctrl+F12 - Pause execution
Ctrl+F2 - Restart debugging
Ctrl+Alt+F2 - Close debugging session
```

### Breakpoints
```
# Setting breakpoints
F2 - Toggle breakpoint at current address
Shift+F2 - Set hardware breakpoint
Ctrl+F2 - Set conditional breakpoint

# Breakpoint types
- Software breakpoints (INT3)
- Hardware breakpoints (debug registers)
- Memory breakpoints (on read/write/execute)
- Conditional breakpoints (with expressions)

# Breakpoint window
View → Breakpoints
Manage all breakpoints in centralized view
```

## Memory Analysis

### Memory Navigation
```
# Memory view
Ctrl+G - Go to address
Ctrl+F - Find pattern in memory
Ctrl+B - Find binary pattern
Ctrl+L - Go to current line in memory view

# Memory operations
Ctrl+E - Edit memory
Ctrl+C - Copy memory
Ctrl+V - Paste to memory
Right-click → Follow in Disassembler/Memory Map
```

### Data Types and Analysis
```
# Data interpretation
Right-click memory → View as:
- Byte/Word/Dword/Qword
- ASCII/Unicode strings
- Float/Double
- Disassembly
- Structure overlay

# Array operations
Right-click → Array → Set array size
Useful for analyzing data structures
```

## Advanced Analysis Features

### Function Analysis
```
# Automatic analysis
Debug → Analysis → Analyze Program
- Function detection
- String references
- Call graph generation
- Cross-reference analysis

# Manual function creation
Ctrl+F - Create function at current address
Edit function boundaries manually
Add function comments and labels
```

### Graph View
```
# Function flow graph
Right-click function → Graph
Visual representation of function control flow
Navigate between basic blocks
Identify loops and conditional branches

# Call graph
View → Graph → Call Graph
Shows function call relationships
Useful for understanding program structure
```

### String Analysis
```
# String references
View → References → Strings
Lists all strings found in memory
Double-click to navigate to usage
Filter by module or address range

# String search
Ctrl+Alt+R - Referenced strings
Search for specific string patterns
Unicode and ASCII string support
```

## Scripting and Automation

### Built-in Commands
```
# Command line interface (bottom panel)
bp 0x401000          # Set breakpoint
bc 0x401000          # Clear breakpoint
dd esp               # Display memory as dwords
da 0x401000          # Display as ASCII string
u 0x401000           # Unassemble at address

# Conditional commands
bp 0x401000, eax==5  # Break when eax equals 5
log "Value: {eax}"   # Log register value
```

### Script Engine
```javascript
// x64dbg script example
var base = Module.GetBase("target.exe");
var entryPoint = base + 0x1000;

// Set breakpoint at entry point
Debug.SetBreakpoint(entryPoint);
log("Breakpoint set at: " + entryPoint.toString(16));

// Continue execution
Debug.Run();

// Wait for breakpoint hit
Debug.Wait();

// Read register values
var eaxValue = Register.Get("eax");
var espValue = Register.Get("esp");

log("EAX: " + eaxValue.toString(16));
log("ESP: " + espValue.toString(16));

// Read memory
var buffer = Memory.Read(espValue, 0x100);
log("Stack content: " + buffer);

// Write memory
Memory.Write(espValue, [0x90, 0x90, 0x90, 0x90]); // NOP sled

// Set register
Register.Set("eax", 1);

// Continue execution
Debug.Run();
```

### Plugin Development
```cpp
// C++ plugin example
#include "pluginmain.h"
#include "plugin.h"

// Plugin initialization
bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    _plugin_logprintf("Custom plugin loaded\n");
    return true;
}

// Plugin setup
void pluginSetup() {
    // Register menu items
    _plugin_menuaddentry(hMenu, MENU_ANALYZE, "Custom Analysis");
    
    // Register callbacks
    _plugin_registercallback(pluginHandle, CB_BREAKPOINT, breakpointCallback);
}

// Breakpoint callback
void breakpointCallback(CBTYPE cbType, void* callbackInfo) {
    PLUG_CB_BREAKPOINT* info = (PLUG_CB_BREAKPOINT*)callbackInfo;
    
    // Custom breakpoint handling
    duint address = info->breakpoint->addr;
    _plugin_logprintf("Breakpoint hit at: %p\n", address);
    
    // Analyze context
    REGDUMP registers;
    DbgGetRegDumpEx(&registers, sizeof(REGDUMP));
    
    // Custom analysis logic
    performCustomAnalysis(address, &registers);
}

void performCustomAnalysis(duint address, REGDUMP* registers) {
    // Read instruction at breakpoint
    unsigned char buffer[16];
    DbgMemRead(address, buffer, sizeof(buffer));
    
    // Disassemble instruction
    DISASM_INSTR instr;
    if(DbgDisasmAt(address, &instr)) {
        _plugin_logprintf("Instruction: %s\n", instr.instruction);
        
        // Check for dangerous functions
        if(strstr(instr.instruction, "strcpy") || 
           strstr(instr.instruction, "sprintf")) {
            _plugin_logprintf("WARNING: Dangerous function call detected!\n");
        }
    }
}
```

## Malware Analysis Workflow

### Dynamic Malware Analysis
```
1. Setup isolated environment (VM)
2. Configure process monitoring
3. Load malware sample
4. Set strategic breakpoints:
   - Entry point
   - API calls (CreateFile, RegSetValue, etc.)
   - Network functions (WSASocket, connect, etc.)
   - Crypto functions (CryptEncrypt, etc.)

5. Monitor execution flow
6. Dump memory regions
7. Extract IOCs (Indicators of Compromise)
8. Document behavior
```

### Anti-Analysis Detection
```javascript
// Detect anti-debugging techniques
function detectAntiDebugging() {
    var base = Module.GetBase("malware.exe");
    
    // Check for IsDebuggerPresent calls
    var isDebuggerPresentAddr = Module.GetProcAddress("kernel32.dll", "IsDebuggerPresent");
    if(isDebuggerPresentAddr) {
        Debug.SetBreakpoint(isDebuggerPresentAddr);
        log("Monitoring IsDebuggerPresent calls");
    }
    
    // Check for timing attacks
    var getTickCountAddr = Module.GetProcAddress("kernel32.dll", "GetTickCount");
    if(getTickCountAddr) {
        Debug.SetBreakpoint(getTickCountAddr);
        log("Monitoring timing checks");
    }
    
    // Monitor VM detection
    searchForVMStrings();
}

function searchForVMStrings() {
    var vmStrings = ["VMware", "VirtualBox", "QEMU", "Xen"];
    
    vmStrings.forEach(function(vmString) {
        var searchResult = Memory.FindString(vmString);
        if(searchResult.length > 0) {
            log("VM detection string found: " + vmString);
            searchResult.forEach(function(addr) {
                log("  at address: " + addr.toString(16));
            });
        }
    });
}
```

### Unpacking Analysis
```javascript
// Automated unpacking detection
function analyzeUnpacking() {
    var base = Module.GetBase("packed.exe");
    var imageSize = Module.GetSize("packed.exe");
    
    // Monitor VirtualAlloc calls
    var virtualAllocAddr = Module.GetProcAddress("kernel32.dll", "VirtualAlloc");
    Debug.SetBreakpoint(virtualAllocAddr, function() {
        var size = Register.Get("edx");  // Size parameter
        var protect = Register.Get("r9d"); // Protection parameter
        
        log("VirtualAlloc called - Size: " + size + ", Protection: " + protect);
        
        // Check for executable memory allocation
        if(protect & 0x40 || protect & 0x20) { // PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ
            log("Executable memory allocated - possible unpacking");
            
            // Set memory breakpoint on allocated region
            Debug.Run(); // Continue to get return value
            Debug.Wait();
            
            var allocatedAddr = Register.Get("eax");
            if(allocatedAddr) {
                Debug.SetMemoryBreakpoint(allocatedAddr, size, "x");
                log("Memory breakpoint set at: " + allocatedAddr.toString(16));
            }
        }
    });
}
```

## Plugin Ecosystem

### Popular Plugins
```
# ScyllaHide - Anti-anti-debugging
- Hides debugger presence from malware
- Bypasses common anti-debugging techniques
- Configurable detection methods

# xAnalyzer - Static analysis
- Automated analysis and commenting
- API call analysis
- String and constant analysis

# x64dbgpy - Python scripting
- Python script support
- Advanced automation capabilities
- Access to all debugging features

# ret-sync - IDA synchronization  
- Synchronize with IDA Pro
- Share analysis between tools
- Enhanced reverse engineering workflow
```

### Custom Analysis Plugin
```cpp
// Memory dump analysis plugin
#include "pluginmain.h"

struct MemoryRegion {
    duint base;
    duint size;
    DWORD protection;
    std::string moduleName;
};

class MemoryAnalyzer {
public:
    void analyzeProcessMemory() {
        std::vector<MemoryRegion> regions = getMemoryRegions();
        
        for(const auto& region : regions) {
            if(isExecutableRegion(region)) {
                analyzeExecutableRegion(region);
            }
        }
    }
    
private:
    std::vector<MemoryRegion> getMemoryRegions() {
        std::vector<MemoryRegion> regions;
        
        // Enumerate memory regions
        MEMORY_BASIC_INFORMATION mbi;
        duint address = 0;
        
        while(DbgMemIsValidReadPtr(address)) {
            if(VirtualQueryEx(DbgGetProcessHandle(), (LPVOID)address, &mbi, sizeof(mbi))) {
                MemoryRegion region;
                region.base = (duint)mbi.BaseAddress;
                region.size = mbi.RegionSize;
                region.protection = mbi.Protect;
                
                char moduleName[MAX_PATH];
                if(DbgGetModuleAt(region.base, moduleName)) {
                    region.moduleName = moduleName;
                }
                
                regions.push_back(region);
                address += mbi.RegionSize;
            } else {
                break;
            }
        }
        
        return regions;
    }
    
    bool isExecutableRegion(const MemoryRegion& region) {
        return (region.protection & PAGE_EXECUTE) ||
               (region.protection & PAGE_EXECUTE_READ) ||
               (region.protection & PAGE_EXECUTE_READWRITE);
    }
    
    void analyzeExecutableRegion(const MemoryRegion& region) {
        _plugin_logprintf("Analyzing executable region: %p - %p (%s)\n", 
                         region.base, region.base + region.size, 
                         region.moduleName.c_str());
        
        // Search for suspicious patterns
        searchForShellcode(region);
        searchForAPIHashing(region);
        searchForEncryption(region);
    }
    
    void searchForShellcode(const MemoryRegion& region) {
        // Common shellcode patterns
        std::vector<std::vector<BYTE>> patterns = {
            {0xEB, 0xFE},  // jmp $ (infinite loop)
            {0x90, 0x90, 0x90, 0x90},  // NOP sled
            {0x31, 0xC0},  // xor eax, eax
            {0xCC, 0xCC, 0xCC, 0xCC}   // INT3 padding
        };
        
        for(const auto& pattern : patterns) {
            duint found = Memory.FindPattern(region.base, region.size, pattern);
            if(found != 0) {
                _plugin_logprintf("Shellcode pattern found at: %p\n", found);
            }
        }
    }
};
```

Comprehensive Windows debugging solution essential for malware analysis, reverse engineering, and vulnerability research.
