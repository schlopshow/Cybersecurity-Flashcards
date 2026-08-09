What is CrackMapExec (CME)?|A tool that helps assess the security of large networks composed of Windows workstations and servers, heavily using the Impacket library for network protocols and post-exploitation techniques
What library does CrackMapExec heavily use?|The Impacket library for working with network protocols and performing post-exploitation techniques
What is NetExec?|A fork of CrackMapExec created after the original project was removed, continuing the project at https://github.com/Pennyw0rth/NetExec
What seven protocols does CrackMapExec support?|SMB (445), WinRM (5985/5986), MSSQL (1433), LDAP (389), SSH (22), RDP (3389), and FTP (21)
What is Poetry in the context of CrackMapExec?|A tool for dependency management and packaging in Python, recommended by CME developers for installation
What target formats does CrackMapExec accept?|A single IP, multiple IPs, CIDR notation, hostname, or a file containing IP addresses/hostnames
What information can be gathered from basic SMB reconnaissance without authentication?|IP address, target local name, Windows version, architecture (x86/x64), FQDN, SMB signing status, and SMB version
What does the --gen-relay-list option do in CrackMapExec?|Extracts all hosts where SMB signing is disabled, useful for NTLM relay attacks with Responder and ntlmrelayx.py
Why is SMB signing important for NTLM relay attacks?|If a computer has SMB signing enabled, you can't relay to it because you'll be unable to prove your attack host's identity
What is a NULL Session?|An anonymous connection to an inter-process communication network service on Windows, allowing attackers to gather information without valid domain credentials
What information can be gathered through a NULL Session on a domain controller?|Domain users (--users), domain groups (--groups), password policy (--pass-pol), and share folders (--shares)
What does the Domain Password Complex flag set to 1 mean?|Passwords must contain characters from at least three categories: uppercase letters, lowercase letters, digits, non-alphanumeric characters, or Unicode alphabetic characters
What is the Account Lockout Threshold?|A policy setting determining the number of failed sign-in attempts that will cause a user account to be locked
What does --rid-brute do in CrackMapExec?|Enumerates users by brute forcing RIDs (Relative Identifiers) up to 4000 by default, useful when NULL authentication is enabled but query restrictions exist
What is a password spray attack?|An attack involving testing a single password against multiple accounts to avoid account lockouts, rather than trying multiple passwords against one account
What does the --continue-on-success option do?|Continues testing all accounts even after finding valid credentials, instead of stopping at the first successful authentication
What does the --no-bruteforce option do?|Uses the 1st user with the 1st password, 2nd user with 2nd password, and so on, instead of trying all password combinations
What does the --local-auth option do?|Tests local accounts instead of domain accounts; cannot be used against Domain Controllers since they don't have a local account database
What are the three colors CrackMapExec displays for authentication results?|Green (valid credentials), Red (invalid credentials), Magenta (valid credentials but authentication unsuccessful)
What does STATUS_PASSWORD_MUST_CHANGE mean?|The username and password are valid but the password must be changed before the account can be used
How can you change a password for an account with STATUS_PASSWORD_MUST_CHANGE?|Using Impacket smbpasswd to set a new password for the target user
What is important to remember about bad password count across protocols?|When using Active Directory authentication, the count of failed password attempts is the same for all protocols combined
What is ASREPRoasting?|An attack looking for users without Kerberos pre-authentication required, allowing anyone to request encrypted data that can be cracked with the user's password
What Hashcat module is used for ASREPRoast hashes?|Module 18200
What three Kerberos error responses help identify user status during Kerberos authentication?|KDC_ERR_C_PRINCIPAL_UNKNOWN (user doesn't exist), KDC_ERR_PREAUTH_FAILED (user exists but wrong password), and "account vulnerable to asreproast attack"
What are the two GPO modules in CrackMapExec for finding credentials?|gpp_password (retrieves plaintext passwords from Group Policy Preferences) and gpp_autologin (searches for autologin information in registry.xml files)
What is the user-desc module?|An LDAP module that queries all users in Active Directory and retrieves their descriptions, filtering by keywords like pass, creds, key, secret, and default
How do you use a module with options in CrackMapExec?|Use the flag -o with options in KEY=value format (msfvenom style)
What is Kerberoasting?|An attack that harvests TGS Tickets from users with servicePrincipalName (SPN) values, where part of the ticket is encrypted with the user's NTLM hash for offline cracking
What Hashcat module is used for Kerberoasting hashes?|Module 13100
What does the --spider option do in CrackMapExec?|Searches in a remote share to find files matching a pattern or regex, with optional content searching using --content
What does the spider_plus module do?|Lists all files in accessible shares and creates a JSON file with share and file information; can also download all content with READ_ONLY=false
How do you retrieve a file from an SMB share with CrackMapExec?|Use --share to specify the share name and --get-file followed by the file path and output filename
How do you upload a file to an SMB share with CrackMapExec?|Use --share to specify the share name and --put-file followed by the local file path and destination name
What is Chisel used for with CrackMapExec?|Setting up a tunnel/proxy to reach networks not directly accessible, used with proxychains to route CME traffic through a compromised host
What is the Slinky module?|A module that creates Windows shortcuts (LNK files) with icon attributes containing UNC paths to a specified SMB server in all writable shares, used to steal NTLMv2 hashes
What is the drop-sc module?|A module that creates .searchConnector-ms files in shared folders to force authentication, an alternative to LNK files for hash stealing
What is the difference between --sessions and --loggedon-users in CrackMapExec?|Sessions mean user credentials are used on the target even though the user isn't logged on; logged-on users means a user has actually logged on to the machine
What does the --computers option do in CrackMapExec?|Enumerates domain computers by performing an LDAP query, though it's available under the SMB protocol
What is LAPS?|Local Administrator Password Solution - provides management of local account passwords of domain-joined computers, stored in Active Directory and protected by ACLs
What does the --rid-brute option enumerate by default?|Objects by brute forcing RIDs up to 4000; can be modified using --rid-brute [MAX_RID]
What does the --disks option do?|Enumerates additional disks that exist on a server
What ports does WMI use?|TCP port 135 and a range of dynamic ports (49152-65535 on Vista/2008+, or 1024-65535 on older systems)
What is the default WMI namespace used by CrackMapExec?|root\cimv2
What does the PASSWD_NOTREQD attribute mean?|The user is not subject to the current password policy length, meaning they could have a shorter password or no password at all
What does the TRUSTED_FOR_DELEGATION attribute indicate?|The service account is trusted for Kerberos delegation, meaning it can impersonate a client requesting the service (Kerberos Unconstrained Delegation)
What does the adminCount attribute value of 1 mean?|The user is protected by the SDProp process, which resets ACL permissions every 60 minutes using the AdminSDHolder as a template; these are often privileged accounts
What is a SID?|Security Identifier - a unique ID number that a computer or domain controller uses to identify a user or domain
What is a gMSA (group Managed Service Account)?|A managed domain account that provides automatic password management, simplified SPN management, and the ability to delegate management across multiple servers
How do you retrieve a gMSA password with CrackMapExec?|Use the --gmsa option with the LDAP protocol when authenticated as a user with PrincipalsAllowedToRetrieveManagedPassword privilege
What does --nla-screenshot do?|Takes a screenshot of the RDP login prompt if NLA (Network Level Authentication) is disabled on the target
What does --screenshot do with RDP?|Takes a screenshot of the RDP session if connection is successful, combinable with --screentime and --res options
What two registry keys control UAC for remote command execution?|LocalAccountTokenFilterPolicy and FilterAdministratorToken under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
What happens when LocalAccountTokenFilterPolicy is set to 0?|Only the built-in administrator account (RID 500) can perform remote administration tasks
What happens when LocalAccountTokenFilterPolicy is set to 1?|All administrator accounts can execute administrative tasks remotely
Does LocalAccountTokenFilterPolicy apply to domain accounts?|No, it only applies to local accounts; domain users in the administrators group can execute commands even with UAC enabled
What are the four SMB command execution methods in CrackMapExec?|wmiexec (via WMI, file on disk), atexec (scheduled task, fileless), smbexec (service creation, fileless), mmcexec (via MMC)
What is the default command execution method order in CrackMapExec?|wmiexec → atexec → smbexec → mmcexec (fails over automatically)
What is the difference between -x and -X in CrackMapExec?|-x executes Windows command line commands; -X executes PowerShell commands
What does CrackMapExec do behind the scenes when running PowerShell with -X?|AMSI bypass, obfuscates the payload, then executes the payload
What is the --amsi-bypass option?|Allows specifying a custom AMSI bypass payload file to use when executing PowerShell commands
Who can use WinRM for command execution?|Members of the Administrators group, members of the Remote Management Users group, or users with explicit PowerShell Remoting permissions
What ports does WinRM use?|HTTP TCP port 5985 and HTTPS TCP port 5986
What is the SAM database?|Security Account Manager database containing credentials for all local users on a Windows machine
What is the ntds.dit file?|A database that stores Active Directory data including user objects, groups, group membership, and password hashes for all users in the domain
What privileges are needed to dump the NTDS database?|Domain Admin account or any account with privileges to perform replication/DCSync
What are LSA Secrets?|A unique protected storage for critical data used by the Local Security Authority, including cached credentials, machine key list, DPAPI keys, and service credentials
What are Domain Cached Credentials (DCC2)?|Hashes stored inside the LSA when a user logs into a workstation; they cannot be used for Pass the Hash attacks and use Hashcat module 2100 to crack
What four LSASS dump modules does CrackMapExec support?|Lsassy (remote credential extraction), Procdump (Microsoft Sysinternals dump), HandleKatz (cloned handles for obfuscated dump), Nanodump (flexible minidump creation)
What does the -H option do in CrackMapExec?|Expects an NTLM hash as an authentication method instead of a password for Pass the Hash attacks
Which protocols support NTLM hash authentication in CrackMapExec?|SMB, WinRM, RDP, LDAP, and MSSQL
What C2 frameworks can integrate with CrackMapExec?|PowerShell Empire (via empire_exec module) and Metasploit (via web_delivery module)
How does CrackMapExec integrate with BloodHound?|By configuring the bh_enabled option in cme.conf, CME automatically marks compromised users and computers as owned in the BloodHound database
What module marks computers as owned in BloodHound?|The bh_owned module, since the default BloodHound integration only marks users as owned
What is the get-network LDAP module?|A module based on Active Directory Integrated DNS dump that retrieves DNS records including IP addresses and/or domain names
What is the MAQ (Machine Account Quota)?|The MS-DS-Machine-Account-Quota attribute indicating how many computer accounts a user can create in a domain, relevant for attacks like Resource Based Constrained Delegation
What is the daclread module?|A module that reads and exports the DACLs of Active Directory objects, useful for finding users with DCSync rights or other sensitive permissions
What does the get_netconnections module do?|Uses WMI to query network connections, retrieving all IP addresses including IPv6 and secondary IPs, plus domain names
What does the ioxidresolver module do?|Uses RPC to query IP addresses of hosts with additional active interfaces, but does not include IPv6 addresses
What is the keepass_discover module?|A module that searches for KeePass-related files and processes on target machines
How does the keepass_trigger module work?|It modifies the KeePass configuration file to add a trigger that automatically exports the database in cleartext, then polls and retrieves the exported data
What five steps are involved in using the keepass_trigger module?|Locate the config file, add the trigger (ACTION=ADD), wait/restart KeePass (ACTION=RESTART), poll the exported data (ACTION=POLL), clean up (ACTION=CLEAN)
What is ZeroLogon (CVE-2020-1472)?|An unauthenticated vulnerability exploitable with network access to a domain controller through a vulnerable Netlogon session to take control of the domain
What is PetitPotam?|An attack technique that allows domain compromise by gaining access to enterprise network infrastructure through NTLM relay using MS-EFSRPC functions
What is noPAC?|A vulnerability allowing escalation of privileges from a regular domain user to domain administrator
What is DFSCoerce?|An NTLM relay attack leveraging the MS-DFSNM protocol to seize control of a Windows domain, requiring a domain user
What is ShadowCoerce?|An attack technique similar to PetitPotam discovered by Lionel Gilles, using shadow copy functionality for NTLM coercion
What is MS17-010 (EternalBlue)?|A critical unauthenticated remote code execution flaw in the SMB service patched by Microsoft in March 2017
How do you run CrackMapExec in debug/verbose mode?|Use the --verbose option before the protocol to see debug logs including logging.debug messages from modules
What is the CME module structure for creating custom modules?|A Python class CMEModule with variables (name, description, supported_protocols, opsec_safe, multiple_hosts) and methods (options, on_login, on_admin_login)
What is the difference between on_login and on_admin_login methods in a CME module?|on_login executes when authenticated but not admin (useful for enumeration); on_admin_login executes when authenticated as admin (can run system commands)
What is audit mode in CrackMapExec?|A mode that replaces passwords or hashes with a character of choice in the output, configured via audit_mode in cme.conf, useful for report screenshots
Does CrackMapExec support IPv6?|Yes, it supports communication over IPv6, which is often enabled by default on Windows but may be less monitored
How do you use Kerberos authentication with CrackMapExec?|Use the -k or --kerberos option with username/password, or use --use-kcache with the KRB5CCNAME environment variable pointing to a ccache file
What advantage does using AES-256 hashes provide for Kerberos authentication?|Traffic looks more like regular Kerberos traffic, representing an operational security (opsec) advantage
What is a ccache file?|A credential cache that holds Kerberos credentials, generally valid as long as the user's session lasts, used via the KRB5CCNAME environment variable
What is cmedb?|A command-line script that facilitates interacting with CrackMapExec's SQLite back-end database, storing credentials, hosts, shares, and groups
Where are CrackMapExec's default databases stored?|~/.cme/workspaces/default/ directory, with an SQLite file for each protocol
What protocols have useful cmedb options?|SMB (creds, hosts, shares, groups, export, import) and MSSQL (creds, hosts, export, import)
How do you use a credential ID from the database with CrackMapExec?|Use the -id option followed by the credential ID number instead of username and password
What export options does cmedb support?|Exporting credentials, hosts, local_admins, and shares in simple or detailed CSV format
What three MSSQL authentication types exist?|Active Directory Account (specify domain), Local Windows Account (use dot as domain), and SQL Account (use --local-auth flag)
What is xp_cmdshell?|An MSSQL extended stored procedure that allows executing Windows operating system commands through SQL, requiring DBA privileges to enable
What does (Pwn3d!) mean for MSSQL authentication?|The authenticated user is a Database Administrator (DBA) who can perform any action against the database
What does the mssql_priv module do?|Enumerates and exploits MSSQL privileges to escalate from standard user to sysadmin via EXECUTE AS LOGIN or db_owner role vectors
What are the three actions of the mssql_priv module?|enum_privs (list privileges, default), privesc (escalate privileges), rollback (remove sysadmin privilege)
How do you transfer files via MSSQL in CrackMapExec?|Use --put-file for uploads and --get-file for downloads, leveraging OPENROWSET and Ole Automation Procedures
What does the spider option --content enable?|Enables searching within file contents rather than just file names when spidering SMB shares
What is the --smb-timeout option used for?|Setting a custom timeout value greater than the default two seconds, useful when transferring large files that fail
What is the completion percentage feature in CrackMapExec?|Pressing enter while a scan is running shows the completion percentage and number of hosts remaining to scan
What is the --key-file option in SSH protocol?|Allows authentication using an SSH private key file in OPENSSH format instead of a password
What does the --exec-method flag do?|Forces CrackMapExec to use only one specific execution method (wmiexec, atexec, smbexec, or mmcexec) instead of automatic failover
What happens when CrackMapExec encounters an opsec unsafe module?|It displays a warning prompt asking if you want to proceed, since the module may write to disk or perform detectable actions
What is the purpose of the --export option in CrackMapExec?|Exports results to a JSON file at the specified full file path, useful for documentation and further processing
How does CrackMapExec handle the Bad Password Count?|When enumerating users with --users, it displays the badpwdcount attribute for each user, helping plan password attack strategies
What is the significance of the Bad Password Count resetting?|It resets to zero if the user authenticates with the correct credentials, which should be factored into password attack timing
