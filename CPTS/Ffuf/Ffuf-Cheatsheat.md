# FFUF Commands Cheat Sheet

## Basic Directory Fuzzing
```bash
ffuf -w /path/to/wordlist:FUZZ -u http://target.com/FUZZ
```

## File Extension Discovery
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://target.com/blog/indexFUZZ
```

## File Fuzzing (with known extension)
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://target.com/blog/FUZZ.php
```

## Recursive Scanning
```bash
ffuf -w /path/to/wordlist:FUZZ -u http://target.com/FUZZ -recursion -recursion-depth 1 -e .php -v
```

## Sub-domain Fuzzing
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.target.com/
```

## VHost Fuzzing
```bash
ffuf -w /path/to/subdomain-wordlist:FUZZ -u http://target.com/ -H 'Host: FUZZ.target.com'
```

## VHost Fuzzing with Filtering
```bash
ffuf -w /path/to/subdomain-wordlist:FUZZ -u http://target.com/ -H 'Host: FUZZ.target.com' -fs 900
```

## GET Parameter Fuzzing
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://target.com/admin.php?FUZZ=key -fs xxx
```

## POST Parameter Fuzzing
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://target.com/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

## Parameter Value Fuzzing
```bash
ffuf -w ids.txt:FUZZ -u http://target.com/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

## Common Options

### Performance
- `-t 200` - Set number of threads (default: 40)
- `-p 0.1` - Add delay between requests
- `-rate 100` - Limit requests per second

### Filtering/Matching
- `-fs 900` - Filter out responses with size 900
- `-fc 404` - Filter out HTTP status code 404
- `-mc 200` - Match only HTTP status code 200
- `-fw 42` - Filter responses with 42 words
- `-fl 10` - Filter responses with 10 lines

### Output
- `-v` - Verbose output (show full URLs)
- `-c` - Colorized output
- `-o output.json` - Save output to file
- `-s` - Silent mode

### Headers and Data
- `-H "Header: Value"` - Add custom header
- `-d "data"` - POST data
- `-X POST` - HTTP method
- `-b "cookie=value"` - Cookie data

## Useful Wordlists

### Directories
- `/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt`
- `/opt/useful/seclists/Discovery/Web-Content/common.txt`

### Files/Extensions
- `/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt`

### Sub-domains
- `/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

### Parameters
- `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`

## Creating Custom Wordlists

### Sequential Numbers (1-1000)
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

### Adding Domain to /etc/hosts
```bash
sudo sh -c 'echo "SERVER_IP  domain.com" >> /etc/hosts'
```

## Tips
- Use `-ic` flag to ignore wordlist comments
- Always filter results appropriately to avoid false positives
- Start with small wordlists and expand if needed
- Use recursive scanning carefully to avoid overwhelming targets
- Consider rate limiting when scanning external targets
