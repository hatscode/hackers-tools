# Autopsy - Digital Forensics Platform

Graphical interface to The Sleuth Kit for digital forensics investigation and analysis.

## Installation

```bash
# Download from official website
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.20.0/autopsy-4.20.0.zip

# Extract and install
unzip autopsy-4.20.0.zip
cd autopsy-4.20.0/unix_setup
sudo sh install.sh

# Start Autopsy
autopsy
```

## Case Management

### Creating Cases
- Multi-user case support
- Evidence organization
- Timeline coordination
- Report generation

### Data Sources
- Disk images (dd, E01, AFF)
- Virtual machine files
- Mobile device backups
- Cloud storage exports

## Analysis Modules

### File System Analysis
- Deleted file recovery
- File signature verification
- Metadata extraction
- Timeline generation

### Keyword Searching
- Index-based searching
- Regular expression support
- Multi-language support
- Hit highlighting

### Hash Analysis
- Known file filtering
- NSRL database integration
- Custom hash sets
- Duplicate detection

## Specialized Modules

### Email Analysis
- PST/OST file parsing
- Email threading
- Attachment extraction
- Metadata analysis

### Web Artifacts
- Browser history analysis
- Cookie examination
- Download tracking
- Bookmark analysis

### Registry Analysis
- Windows registry parsing
- System configuration
- User activity tracking
- Software installation history

## Mobile Forensics

### iOS Support
- iTunes backup analysis
- Plist file parsing
- SQLite database extraction
- Application data recovery

### Android Support
- ADB backup processing
- SQLite database analysis
- Application package examination
- System log analysis

## Network Integration

### Central Repository
- Multi-case correlation
- Hash set management
- Tag synchronization
- User coordination

### Timeline Analysis
- Super timeline creation
- Event correlation
- Activity reconstruction
- Visual timeline interface

## Reporting Features

### Report Types
- Executive summary
- Technical analysis report
- Timeline reports
- Keyword hit reports

### Export Options
- HTML reports
- PDF generation
- CSV data export
- XML case export

## Plugin Architecture

- Third-party module support
- Custom analyzer development
- Python scripting interface
- Java plugin framework

Professional digital forensics platform with comprehensive analysis capabilities.
