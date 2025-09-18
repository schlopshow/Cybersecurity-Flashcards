# Web Proxy Commands Cheat Sheet

## Proxychains Configuration
```bash
# Edit proxychains configuration
/etc/proxychains.conf

# Add HTTP proxy configuration (comment out socks4 line)
#socks4 127.0.0.1 9050
http 127.0.0.1 8080

# Enable quiet mode (uncomment)
quiet_mode
```

## Proxychains Usage
```bash
# Route cURL through proxy
proxychains curl http://SERVER_IP:PORT

# Route any command through proxy
proxychains <command>
```

## Nmap with Proxy
```bash
# Use nmap with HTTP proxy
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC

# Check nmap proxy options
nmap -h | grep -i prox
```

## Metasploit with Proxy
```bash
# Start Metasploit
msfconsole

# Set proxy for any exploit/module
set PROXIES HTTP:127.0.0.1:8080

# Example with robots_txt scanner
use auxiliary/scanner/http/robots_txt
set PROXIES HTTP:127.0.0.1:8080
set RHOST SERVER_IP
set RPORT PORT
run
```

## Burp Suite Shortcuts
```
Ctrl+I - Send to Intruder
Ctrl+R - Send to Repeater
Ctrl+Shift+I - Go to Intruder
Ctrl+U - URL encode selection (in Repeater)
Ctrl+Shift+R - Force full refresh in browser
```

## ZAP Shortcuts
```
Ctrl+B - Toggle request interception
Ctrl+R - Access Replacer
Ctrl+E - Open Encoder/Decoder/Hash
```

## Burp Suite Navigation
```
Proxy > Options > Match and Replace - Automatic modifications
Proxy > Options > Intercept Server Responses - Enable response interception
Target > Site map - View discovered sites/directories
Target > Scope - Configure scan scope
Extender > BApp Store - Install extensions
```

## ZAP Navigation
```
Tools > Options > Replacer - Automatic replacements
Report > Generate HTML Report - Export scan results
Manage Add-ons > Marketplace - Install add-ons
```

## Common Proxy Configurations
```
# Default Burp proxy
127.0.0.1:8080

# Default ZAP proxy
127.0.0.1:8080

# HTTPS proxy setup requires importing CA certificates
```

## URL Encoding Key Characters
```
Space: %20
&: %26
#: %23
```

## Burp Intruder Attack Types
- **Sniper**: Single position, single wordlist
- **Battering Ram**: Multiple positions, same wordlist
- **Pitchfork**: Multiple positions, multiple wordlists (parallel)
- **Cluster Bomb**: Multiple positions, multiple wordlists (all combinations)

## Scanner Configuration Examples
```
# Burp Scanner configurations
- Crawl strategy - fastest
- Audit checks - critical issues only
- Crawl limit - 10 minutes

# ZAP Scanner modes
- Standard Spider
- Ajax Spider (for JavaScript-heavy sites)
```

## Useful Wordlist Locations
```
# SecLists common directory wordlist
/opt/useful/seclists/Discovery/Web-Content/common.txt

# FuzzDB wordlists (via ZAP add-on)
fuzzdb > attack > os-cmd-execution
```
