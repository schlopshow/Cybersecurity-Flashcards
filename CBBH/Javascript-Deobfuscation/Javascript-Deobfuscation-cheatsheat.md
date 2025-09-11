# JavaScript Deobfuscation & Analysis Cheat Sheet

## **Identifying Obfuscation Types**
- **Minified**: Single long line of code
- **Packed**: Recognizable by `function(p,a,c,k,e,d)` pattern
- **Advanced**: No clear text strings visible, heavily encoded

## **Encoding Identification**
- **Base64**: Alpha-numeric + `+` `/` with `=` padding, length multiple of 4
- **Hex**: Only 0-9 and a-f characters
- **Rot13**: Scrambled text but maintains some resemblance to original

## **Essential Commands**

### Base64 Operations
```bash
# Encode
echo "text" | base64

# Decode
echo "encoded_text" | base64 -d
```

### Hex Operations
```bash
# Encode
echo "text" | xxd -p

# Decode
echo "hex_string" | xxd -p -r
```

### Rot13 Operations
```bash
# Encode/Decode (same command)
echo "text" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

### Web Requests
```bash
# Basic GET
curl http://URL

# POST request
curl -s http://URL -X POST

# POST with data
curl -s http://URL -X POST -d "param1=value"
```

### Browser Developer Tools
- **Firefox debugger**: `CTRL+SHIFT+Z`
- **View source**: `CTRL+U`
- **Pretty print**: Click `{ }` button in debugger

## **Analysis Workflow**
1. **View HTML source** → Look for external JS files
2. **Check JS files** → Identify obfuscation type
3. **Beautify code** → Use browser dev tools or online tools
4. **Deobfuscate** → Use tools like UnPacker for packed code
5. **Decode strings** → Identify and decode base64/hex/rot13
6. **Analyze functionality** → Look for HTTP requests, hidden functions

## **Useful Online Tools**
- **Beautifiers**: Prettier, Beautifier
- **Deobfuscators**: UnPacker, obfuscator.io
- **Testing**: JSConsole, jsconsole.com
- **Encoding detection**: Cipher Identifier

## **Key Analysis Points**
- Look for **XMLHttpRequest** objects (web requests)
- Check for **hidden POST requests** to undocumented endpoints
- Search for **cleartext strings** in obfuscated code
- Examine **function names** that reveal functionality
- Test **deobfuscated functions** in browser console

## **Security Notes**
- Client-side authentication/encryption is vulnerable
- Obfuscation ≠ security (can be reversed)
- Always analyze suspicious JavaScript for malicious behavior
- Check for encoded payloads that decode at runtime
