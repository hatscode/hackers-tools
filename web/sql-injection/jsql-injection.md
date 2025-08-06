# jSQL Injection - Graphical SQL Injection Tool

Java-based graphical application for automated SQL injection testing with intuitive interface.

## Installation

```bash
# Download latest release
wget https://github.com/ron190/jsql-injection/releases/download/v0.82/jsql-injection-v0.82.jar

# Java requirement check
java -version

# Run application
java -jar jsql-injection-v0.82.jar

# Alternative: AppImage version
wget https://github.com/ron190/jsql-injection/releases/download/v0.82/jsql-injection-v0.82.AppImage
chmod +x jsql-injection-v0.82.AppImage
./jsql-injection-v0.82.AppImage
```

## Basic Configuration

### Connection Setup
1. Enter target URL in address bar
2. Configure injection method (GET/POST/Header/Cookie)
3. Set request parameters
4. Choose database type (auto-detect or manual)
5. Configure authentication if needed

### Request Customization
- **Headers**: Add custom HTTP headers
- **Cookies**: Set session cookies
- **User Agent**: Modify user agent string
- **Proxy**: Configure proxy settings
- **Authentication**: Basic/NTLM/Digest auth

## Database Enumeration Features

### Information Gathering
- Database version detection
- Current user identification
- Database name enumeration
- Privilege assessment
- Schema discovery

### Table and Column Discovery
- Automatic table enumeration
- Column name detection
- Data type identification
- Primary key discovery
- Foreign key relationships

## Data Extraction

### Manual Extraction
- Custom SQL query execution
- Result set browsing
- Data export options
- Binary data handling

### Automated Dumping
- Entire database extraction
- Selective table dumping
- Column-specific extraction
- Filtered data retrieval

## Advanced Features

### File System Access
- File reading capabilities
- File writing (when possible)
- Directory listing
- Path traversal testing

### Command Execution
- OS command execution
- Shell access (when available)
- Process enumeration
- System information gathering

## Injection Techniques

### Supported Methods
- **Boolean-based blind**: True/false condition testing
- **Time-based blind**: Delay-based detection
- **Error-based**: Database error message exploitation
- **Union-based**: UNION SELECT exploitation
- **Stacked queries**: Multiple query execution

### Database Support
- MySQL
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- H2
- HSQLDB
- Derby
- Firebird
- Access

## Evasion Capabilities

### WAF Bypass
- Character encoding variations
- Comment insertion
- Case variation
- String concatenation
- Hex encoding

### Stealth Options
- Request throttling
- Random delays
- User agent rotation
- Connection pooling

## Batch Processing

### Multiple Targets
- URL list processing
- Parameter permutation
- Credential testing
- Result aggregation

### Automation Scripts
- Custom injection payloads
- Response parsing rules
- Export configurations
- Reporting templates

## Integration Features

### Import Options
- Burp Suite request files
- Raw HTTP requests
- Parameter lists
- Cookie jar files

### Export Capabilities
- CSV data export
- JSON result format
- XML report generation
- HTML report creation

## Configuration Management

### Profile Settings
- Connection profiles
- Injection templates
- Payload libraries
- Response parsers

### Performance Tuning
- Thread count optimization
- Timeout configurations
- Memory allocation
- Cache settings

## Practical Usage Examples

### Web Application Testing
1. Load target application URL
2. Configure authentication if required
3. Run automatic parameter detection
4. Execute injection tests
5. Extract sensitive data
6. Generate assessment report

### API Security Testing
1. Import API request templates
2. Configure JSON/XML parameters
3. Test API endpoints
4. Extract database information
5. Assess data exposure

### Blind Injection Testing
1. Configure time-based detection
2. Set optimal delay thresholds
3. Execute automated extraction
4. Monitor progress indicators
5. Export extracted data

## Reporting Features

### Built-in Reports
- Vulnerability summary
- Technical details
- Exploitation evidence
- Remediation guidance

### Custom Reports
- Template customization
- Logo and branding
- Executive summaries
- Technical appendices

## Security Considerations

### Responsible Testing
- Only test authorized systems
- Minimize data exposure
- Avoid system damage
- Document findings appropriately

### Legal Compliance
- Obtain proper authorization
- Follow disclosure timelines
- Respect data privacy
- Maintain evidence integrity

## Performance Optimization

### Memory Management
- Adjust heap size: `java -Xmx2g -jar jsql-injection.jar`
- Enable garbage collection logging
- Monitor memory usage
- Optimize result caching

### Network Configuration
- Configure connection timeouts
- Set retry mechanisms
- Implement connection pooling
- Monitor bandwidth usage

## Troubleshooting

### Common Issues
- Java version compatibility
- Network connectivity problems
- Authentication failures
- WAF blocking

### Debug Options
- Enable verbose logging
- Network traffic monitoring
- Response analysis tools
- Performance profiling

## Best Practices

### Testing Methodology
1. Start with minimal risk settings
2. Gradually increase test complexity
3. Document all findings
4. Validate results manually
5. Generate comprehensive reports

### Data Protection
- Limit data extraction
- Secure extracted information
- Use encrypted storage
- Implement access controls

User-friendly alternative to command-line SQL injection tools with comprehensive graphical interface for security professionals.
