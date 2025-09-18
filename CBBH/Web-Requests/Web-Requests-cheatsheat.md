# cURL Command Cheat Sheet

## Basic Usage
```bash
curl <url>                           # Basic HTTP GET request
curl -s <url>                        # Silent mode (no progress output)
curl -v <url>                        # Verbose output (shows full request/response)
curl -vvv <url>                      # Even more verbose output
```

## Output Control
```bash
curl -o filename <url>               # Save output to specified filename
curl -O <url>                        # Save output using remote filename
curl -s -O <url>                     # Silent download to remote filename
```

## HTTP Methods
```bash
curl -X GET <url>                    # GET request (default)
curl -X POST <url>                   # POST request
curl -X PUT <url>                    # PUT request
curl -X DELETE <url>                 # DELETE request
curl -X HEAD <url>                   # HEAD request
curl -X OPTIONS <url>                # OPTIONS request
```

## Headers and Authentication
```bash
curl -H "Header: Value" <url>        # Add custom header
curl -H "Content-Type: application/json" <url>  # Set content type
curl -u username:password <url>      # Basic authentication
curl -A "User-Agent-String" <url>    # Set user agent
```

## Cookies
```bash
curl -b "cookie=value" <url>         # Send cookie
curl -b "PHPSESSID=sessionid" <url>  # Send session cookie
curl -H "Cookie: name=value" <url>   # Send cookie as header
```

## POST Data
```bash
curl -X POST -d "data" <url>         # Send POST data
curl -X POST -d "param1=value1&param2=value2" <url>  # Form data
curl -X POST -d '{"key":"value"}' <url>  # JSON data
curl -X POST -d '{"key":"value"}' -H "Content-Type: application/json" <url>  # JSON with proper header
```

## API Operations (CRUD)
```bash
# Create (POST)
curl -X POST -d '{"city_name":"City", "country_name":"Country"}' -H 'Content-Type: application/json' <url>/api/city/

# Read (GET)
curl <url>/api/city/                 # Get all entries
curl <url>/api/city/london           # Get specific entry
curl -s <url>/api/city/london | jq   # Get and format JSON

# Update (PUT)
curl -X PUT -d '{"city_name":"New_City", "country_name":"Country"}' -H 'Content-Type: application/json' <url>/api/city/old_city

# Delete (DELETE)
curl -X DELETE <url>/api/city/cityname
```

## Redirection and Response Handling
```bash
curl -L <url>                        # Follow redirects
curl -i <url>                        # Include response headers in output
```

## Help and Manual
```bash
curl -h                              # Basic help
curl --help all                     # Full help
curl --help category                 # Help for specific category (e.g., --help http)
man curl                             # Full manual page
```

## Browser DevTools Integration
- Right-click on network request → Copy → Copy as cURL
- Use browser Network tab to inspect HTTP requests/responses
- Access DevTools: F12 or Ctrl+Shift+I
- Storage tab (Shift+F9) for cookie management
- Console tab for running Fetch API requests
