# Dirbuster - GUI Directory Brute Forcer

Java-based GUI application for directory and file brute forcing.

## Installation

```bash
# Ubuntu/Debian
apt-get install dirbuster

# Manual installation
wget https://sourceforge.net/projects/dirbuster/files/DirBuster%20%28jar%20%2B%20lists%29/1.0-RC1/DirBuster-1.0-RC1.tar.bz2
tar -xjf DirBuster-1.0-RC1.tar.bz2
```

## Starting the Application

```bash
# Launch GUI
dirbuster

# Command line (if available)
java -jar DirBuster-1.0-RC1.jar
```

## Configuration Options

### Target Settings
- Target URL specification
- Port configuration  
- HTTP method selection
- Authentication setup

### Threading Options
- Number of threads (1-500)
- Request throttling
- Connection timeout

### Wordlist Selection
- Built-in wordlists
- Custom wordlist import
- Extension specification
- Case sensitivity

## Built-in Wordlists

Includes comprehensive wordlists:
- directory-list-2.3-medium.txt
- directory-list-2.3-big.txt  
- directory-list-2.3-small.txt
- apache-user-enum-1.0.txt
- apache-user-enum-2.0.txt

## Advanced Features

### Fuzzing Options
- Blank extension fuzzing
- Be recursive scanning
- File extension bruteforce
- Custom URL manipulation

### Response Analysis
- Status code filtering
- Response size analysis
- Content-based filtering
- Regular expression matching

## Output Options

- Real-time result viewing
- Export to various formats
- Report generation
- Screenshot capability

## Performance Considerations

GUI-based tool may consume more resources than command-line alternatives.
