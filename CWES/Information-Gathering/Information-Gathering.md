# Web Reconnaissance Commands Cheat Sheet

## WHOIS Commands
```bash
# Install WHOIS
sudo apt install whois -y

# Basic WHOIS lookup
whois domain.com
```

## DNS Commands
```bash
# Basic DNS lookup
dig domain.com

# Specific record types
dig domain.com A        # IPv4 address
dig domain.com AAAA     # IPv6 address
dig domain.com MX       # Mail servers
dig domain.com NS       # Name servers
dig domain.com TXT      # Text records
dig domain.com CNAME    # Canonical name
dig domain.com SOA      # Start of authority

# Specify DNS server
dig @1.1.1.1 domain.com

# Show full resolution path
dig +trace domain.com

# Reverse DNS lookup
dig -x 192.168.1.1

# Short output only
dig +short domain.com

# Zone transfer attempt
dig axfr @nameserver domain.com
```

## Subdomain Enumeration
```bash
# DNSEnum
dnsenum --enum domain.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r

# Gobuster for virtual hosts
gobuster vhost -u http://target_IP -w wordlist_file --append-domain
```

## Certificate Transparency
```bash
# Query crt.sh for subdomains containing 'dev'
curl -s "https://crt.sh/?q=domain.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

## Web Fingerprinting
```bash
# Banner grabbing with curl
curl -I http://domain.com
curl -I https://domain.com

# WAF detection
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f domain.com

# Nikto scanning (fingerprinting only)
nikto -h domain.com -Tuning b
```

## Web Crawling
```bash
# Install Scrapy
pip3 install scrapy

# Download and run ReconSpider
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://domain.com
```

## Automated Reconnaissance
```bash
# FinalRecon installation
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py

# FinalRecon usage examples
./finalrecon.py --url http://domain.com --headers --whois
./finalrecon.py --url http://domain.com --full
```

## Google Dorking Examples
```
# Finding login pages
site:domain.com inurl:login
site:domain.com (inurl:login OR inurl:admin)

# Identifying exposed files
site:domain.com filetype:pdf
site:domain.com (filetype:xls OR filetype:docx)

# Configuration files
site:domain.com inurl:config.php
site:domain.com (ext:conf OR ext:cnf)

# Database backups
site:domain.com inurl:backup
site:domain.com filetype:sql
```

## Key URLs to Check
```
# Standard reconnaissance paths
http://domain.com/robots.txt
http://domain.com/.well-known/
http://domain.com/.well-known/security.txt
http://domain.com/.well-known/openid-configuration

# Certificate transparency
https://crt.sh/?q=domain.com

# Wayback machine
https://web.archive.org/web/*/domain.com
```
