# jSQL Injection - Java-based SQL Injection Tool

Advanced SQL injection testing tool with comprehensive database support and GUI interface.

## Installation

```bash
# Download from GitHub releases
wget https://github.com/ron190/jsql-injection/releases/download/v0.97/jsql-injection-v0.97.jar

# Run application
java -jar jsql-injection-v0.97.jar
```

## GUI Interface Features

### Connection Testing
- URL validation and testing
- Request/response analysis  
- Custom header support
- Cookie management

### Injection Techniques
- Boolean-based blind
- Error-based injection
- Time-based blind
- UNION query injection
- Stacked queries

## Supported Databases

```bash
# Major database systems
- MySQL
- PostgreSQL
- Oracle
- SQL Server
- SQLite
- H2
- Derby
- HSQLDB
- Informix
- Access
```

## Advanced Features

### Multi-threading
Parallel injection testing for faster results

### Request Customization
- HTTP method selection
- Custom headers and parameters
- Authentication support
- Proxy configuration

### Data Extraction
- Database enumeration
- Table and column discovery
- Data dumping capabilities
- File system access

## Automation Capabilities

```bash
# Command line usage
java -jar jsql-injection.jar \
  --url="http://example.com/page?id=1" \
  --method=GET \
  --header="User-Agent: Custom" \
  --technique=BEUST
```

### Batch Processing
- Multiple URL testing
- Result aggregation
- Report generation
- Integration support

## Security Features

### WAF Evasion
- Encoding techniques
- Obfuscation methods
- Rate limiting
- Random delays

### Safe Testing
- Read-only operations option
- Damage prevention controls
- Transaction rollback support

## Integration Options

- Burp Suite extension
- OWASP ZAP integration
- Custom script support
- API endpoints

## Reporting

Comprehensive reporting with:
- Vulnerability details
- Exploitation steps
- Remediation advice
- Technical evidence
