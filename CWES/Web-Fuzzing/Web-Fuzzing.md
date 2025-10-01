# Web Fuzzing Commands Cheat Sheet

## Installation

### Install Go, Python, and PIPX
```bash
sudo apt update
sudo apt install -y golang
sudo apt install -y python3 python3-pip
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global
```

### Install Fuzzing Tools
```bash
# FFUF
go install github.com/ffuf/ffuf/v2@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest

# FeroxBuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin

# wenum (wfuzz fork)
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

## FFUF Commands

### Basic Directory Fuzzing
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
```

### File Fuzzing with Extensions
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/directory/FUZZ.html -e .php,.html,.txt,.bak,.js -v
```

### Recursive Fuzzing
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
```

### Recursive Fuzzing with Depth and Rate Limit
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```

### POST Parameter Fuzzing
```bash
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```

## wenum (wfuzz) Commands

### GET Parameter Value Fuzzing
```bash
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"
```

## Gobuster Commands

### VHost Fuzzing
```bash
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```

### Subdomain Enumeration
```bash
gobuster dns -d inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Directory Fuzzing with Filtering
```bash
gobuster dir -u http://example.com/ -w wordlist.txt -s 200,301 --exclude-length 0
```

## curl Commands

### Test GET Parameter
```bash
curl http://IP:PORT/get.php?x=value
```

### Test POST Parameter
```bash
curl -d "y=value" http://IP:PORT/post.php
```

### Empty POST Request
```bash
curl -d "" http://IP:PORT/post.php
```

## Common Wordlists

### Directory/File Fuzzing
- `/usr/share/seclists/Discovery/Web-Content/common.txt` - General purpose
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` - Directory focused
- `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` - Large directory collection
- `/usr/share/seclists/Discovery/Web-Content/big.txt` - Massive directory and file list

### Subdomain Enumeration
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` - Top 5000 subdomains

## Key Flags Reference

### FFUF
- `-w` - Wordlist path
- `-u` - Target URL (use FUZZ keyword)
- `-e` - File extensions
- `-v` - Verbose output
- `-ic` - Ignore comments in wordlist
- `-recursion` - Enable recursive fuzzing
- `-recursion-depth` - Maximum recursion depth
- `-rate` - Requests per second limit
- `-mc` - Match HTTP status codes
- `-X` - HTTP method (GET, POST, etc.)
- `-H` - Add HTTP header
- `-d` - POST data

### wenum/wfuzz
- `-w` - Wordlist path
- `-u` - Target URL (use FUZZ keyword)
- `--hc` - Hide responses with status code
- `-d` - POST data

### Gobuster
- `vhost` - VHost fuzzing mode
- `dns` - DNS/subdomain enumeration mode
- `dir` - Directory fuzzing mode
- `-u` - Target URL
- `-d` - Target domain
- `-w` - Wordlist path
- `--append-domain` - Append base domain to wordlist entries
- `-s` - Include specific status codes
- `-b` - Exclude specific status codes
- `--exclude-length` - Exclude specific content lengths

## Useful Additions

### Add Host to /etc/hosts
```bash
echo "IP hostname.htb" | sudo tee -a /etc/hosts
```

### Check Tool Versions
```bash
go version
python3 --version
```
