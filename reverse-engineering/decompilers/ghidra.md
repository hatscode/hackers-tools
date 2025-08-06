# Ghidra - Software Reverse Engineering Framework

NSA-developed open-source reverse engineering framework for analyzing compiled software across multiple platforms and architectures.

## Installation

```bash
# Download from NSA GitHub
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
unzip ghidra_10.4_PUBLIC_20230928.zip
cd ghidra_10.4_PUBLIC

# Prerequisites
# Java 17+ required
sudo apt install openjdk-17-jdk

# Launch Ghidra
./ghidraRun

# Linux package installation
sudo apt install ghidra

# Docker installation
docker run -it --rm -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY=$DISPLAY ghidra
```

## Basic Project Setup

### Creating Projects
```bash
# Start Ghidra
./ghidraRun

# Create new project
File → New Project → Non-Shared Project
# Set project directory and name

# Import binary
File → Import File
# Select binary to analyze
# Configure import options (architecture, language, format)
```

### Supported Architectures
- x86/x64 (32-bit and 64-bit Intel/AMD)
- ARM/AARCH64 (32-bit and 64-bit ARM)
- MIPS (32-bit and 64-bit)
- PowerPC (32-bit and 64-bit) 
- SPARC (32-bit and 64-bit)
- 6502, 6805, 68000
- PIC (16-bit, 18-bit, 24-bit)
- AVR, MSP430
- And many others

## Core Analysis Features

### Auto-Analysis
```
# Initial analysis
Analysis → Auto Analyze → [Binary Name]

# Analysis options:
☑ ASCII Strings
☑ Call Convention ID
☑ Create Address Tables  
☑ Data Reference
☑ Decompiler Parameter ID
☑ Demangler GNU
☑ Disassemble Entry Points
☑ Function ID
☑ Reference
☑ Stack
☑ Subroutine References
☑ Windows PE RTTI Analyzer
```

### Manual Analysis Workflow
```
1. Load binary and run auto-analysis
2. Examine entry points and main functions
3. Analyze string references
4. Identify function calls and cross-references
5. Use decompiler for high-level view
6. Annotate functions and variables
7. Export analysis results
```

## Code Browser Interface

### Main Windows
- **Listing**: Assembly code view with addresses and instructions
- **Decompiler**: C-like pseudocode representation  
- **Symbol Tree**: Functions, labels, and namespaces
- **Data Type Manager**: Structures, unions, and data types
- **Program Tree**: Organized view of program sections

### Navigation
```
# Keyboard shortcuts
G - Go to address/symbol
Ctrl+H - Show call hierarchy
Ctrl+Shift+E - Show references to
L - Set label
; - Add comment
Ctrl+L - Retype variable
F - Create function
U - Clear function
```

## Decompiler Features

### Function Analysis
```c
// Example decompiled function
undefined8 main(int argc, char **argv)
{
    int choice;
    char buffer[64];
    
    printf("Enter choice: ");
    scanf("%d", &choice);
    
    if (choice == 1) {
        printf("Enter name: ");
        gets(buffer);  // Vulnerable function identified
        printf("Hello %s\n", buffer);
    }
    
    return 0;
}
```

### Variable Renaming and Retyping
```c
// Before analysis
undefined8 FUN_00401000(undefined4 param_1, undefined8 param_2)
{
    undefined auStack_48[64];
    // ...
}

// After analysis and annotation
int authenticate_user(int user_id, char *password)
{
    char password_buffer[64];
    // ...
}
```

## Scripting and Automation

### Python Scripting
```python
# Ghidra Python script example
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit

# Get current program
program = getCurrentProgram()
listing = program.getListing()

# Find all functions
function_manager = program.getFunctionManager()
functions = function_manager.getFunctions(True)

# Analyze each function
for func in functions:
    func_name = func.getName()
    entry_point = func.getEntryPoint()
    
    print(f"Function: {func_name} at {entry_point}")
    
    # Get function body
    body = func.getBody()
    instructions = listing.getInstructions(body, True)
    
    # Look for dangerous function calls
    dangerous_calls = ["strcpy", "sprintf", "gets", "scanf"]
    
    for instruction in instructions:
        mnemonic = instruction.getMnemonicString()
        if mnemonic == "CALL":
            operands = instruction.getOpObjects(0)
            for operand in operands:
                if hasattr(operand, 'toString'):
                    call_target = operand.toString()
                    for dangerous in dangerous_calls:
                        if dangerous in call_target:
                            print(f"  Dangerous call found: {call_target}")
```

### Java API Examples
```java
// Ghidra Java script example
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class FindVulnerabilities extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        // Find buffer overflow vulnerabilities
        FunctionIterator functions = funcMgr.getFunctions(true);
        while (functions.hasNext()) {
            Function func = functions.next();
            analyzeFunction(func);
        }
    }
    
    private void analyzeFunction(Function func) {
        AddressSetView body = func.getBody();
        InstructionIterator instructions = 
            currentProgram.getListing().getInstructions(body, true);
        
        while (instructions.hasNext()) {
            Instruction inst = instructions.next();
            
            // Check for dangerous function calls
            if (inst.getMnemonicString().equals("CALL")) {
                String target = inst.getDefaultOperandRepresentation(0);
                if (target.contains("strcpy") || target.contains("gets")) {
                    println("Potential buffer overflow at: " + 
                           inst.getAddress() + " in function " + func.getName());
                }
            }
        }
    }
}
```

## Advanced Analysis Techniques

### Structure Recovery
```c
// Define custom structures
struct user_data {
    int user_id;
    char username[32];
    char password[32];
    int privilege_level;
};

// Apply to memory locations
// Select data → Right-click → Data → Choose Data Type
```

### Function Signature Analysis
```c
// Before signature analysis
undefined4 FUN_00401234(undefined4 param_1, undefined4 param_2)

// After applying calling convention and parameter analysis
int validate_credentials(char *username, char *password)
```

### Cross-References Analysis
```
# View references to/from functions
Right-click function → Show References to
Ctrl+Shift+E → References to [function]

# Reference types:
- Call references (function calls)
- Data references (global variables)
- Read/Write references (memory access)
- Jump references (control flow)
```

## Binary Analysis Workflows

### Malware Analysis
```python
# Malware analysis script
def analyze_malware():
    program = getCurrentProgram()
    
    # Look for suspicious strings
    strings = find_suspicious_strings()
    
    # Identify crypto functions
    crypto_functions = find_crypto_usage()
    
    # Analyze network functionality
    network_calls = find_network_calls()
    
    # Check for anti-analysis techniques
    anti_debug = find_anti_debug_techniques()
    
    # Generate report
    generate_malware_report(strings, crypto_functions, network_calls, anti_debug)

def find_suspicious_strings():
    suspicious_patterns = [
        "cmd.exe", "powershell", "CreateProcess",
        "WriteFile", "RegSetValue", "GetProcAddress"
    ]
    
    found_strings = []
    memory = getCurrentProgram().getMemory()
    
    # Search for defined strings
    for string_data in getCurrentProgram().getListing().getDefinedData(True):
        if string_data.hasStringValue():
            string_value = string_data.getDefaultValueRepresentation()
            for pattern in suspicious_patterns:
                if pattern.lower() in string_value.lower():
                    found_strings.append({
                        'address': string_data.getAddress(),
                        'value': string_value,
                        'pattern': pattern
                    })
    
    return found_strings
```

### Vulnerability Research
```python
# Vulnerability hunting script
def find_vulnerabilities():
    dangerous_functions = {
        'strcpy': 'Buffer overflow risk',
        'sprintf': 'Format string vulnerability',
        'gets': 'Buffer overflow risk',
        'scanf': 'Input validation issue',
        'strcat': 'Buffer overflow risk'
    }
    
    vulnerabilities = []
    function_manager = getCurrentProgram().getFunctionManager()
    
    for func in function_manager.getFunctions(True):
        # Analyze function for dangerous calls
        vulns = analyze_function_vulnerabilities(func, dangerous_functions)
        vulnerabilities.extend(vulns)
    
    return vulnerabilities

def analyze_function_vulnerabilities(function, dangerous_funcs):
    vulnerabilities = []
    listing = getCurrentProgram().getListing()
    
    instructions = listing.getInstructions(function.getBody(), True)
    
    for instruction in instructions:
        if instruction.getMnemonicString() == "CALL":
            call_target = get_call_target(instruction)
            
            for dangerous_func, risk in dangerous_funcs.items():
                if dangerous_func in call_target:
                    vulnerabilities.append({
                        'function': function.getName(),
                        'address': instruction.getAddress(),
                        'call': dangerous_func,
                        'risk': risk
                    })
    
    return vulnerabilities
```

## Plugin Development

### Custom Analyzer Plugin
```java
public class CustomAnalyzer extends AbstractAnalyzer {
    
    public CustomAnalyzer() {
        super("Custom Vulnerability Analyzer", 
              "Finds potential security vulnerabilities", 
              AnalyzerType.BYTE_ANALYZER);
    }
    
    @Override
    public boolean added(Program program, AddressSetView set, 
                        TaskMonitor monitor, MessageLog log) {
        
        // Analysis implementation
        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(set, true);
        
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            analyzeForVulnerabilities(program, func, monitor, log);
        }
        
        return true;
    }
    
    private void analyzeForVulnerabilities(Program program, Function func,
                                          TaskMonitor monitor, MessageLog log) {
        // Custom vulnerability analysis logic
    }
}
```

## Integration and Export

### Export Options
```
# Export decompiled code
File → Export Program → C/C++
File → Export Program → XML

# Generate reports
File → Export Program → Html
File → Export Program → ASCII

# Database export
File → Export Program → GZF (Ghidra Zip File)
```

### Version Control Integration
```bash
# Export Ghidra project for version control
# Projects can be exported as .gzf files

# Command line export
analyzeHeadless /path/to/projects ProjectName -import /path/to/binary -scriptPath /path/to/scripts -postScript ExportScript.py

# Batch processing
analyzeHeadless /projects BatchProject -import /binaries/*.exe -recursive -processor x86:LE:64:default
```

## Performance Optimization

### Analysis Settings
```
# Optimize for large binaries
Edit → Tool Options → Analysis
- Disable unnecessary analyzers
- Adjust decompiler timeout settings
- Configure memory limits

# Parallel processing
Analysis → One Shot → Configure parallel analysis
```

### Memory Management
```
# Increase heap size
export GHIDRA_JAVA_OPTS="-Xmx8G"

# Configure in ghidraRun script
MAXMEM="8G"
```

Powerful and comprehensive reverse engineering platform essential for binary analysis, vulnerability research, and malware analysis.
