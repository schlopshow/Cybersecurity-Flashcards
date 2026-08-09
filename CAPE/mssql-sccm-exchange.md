What is SCCM (System Center Configuration Manager)?|A Microsoft software for centralized management of servers and workstations in large Active Directory environments, offering functions like installing/uninstalling applications, configuring network parameters, deploying patches, running scripts, and deploying operating systems
What are the current names for SCCM?|Microsoft Endpoint Configuration Manager (MECM) and more recently Microsoft Configuration Manager (ConfigMgr)
What is the difference between SCCM and Intune?|SCCM is an on-premise solution while Intune is a cloud-native client management suite; both are part of the Microsoft Endpoint Manager umbrella
What is the Primary Server in SCCM architecture?|The central point of the system responsible for the SCCM site, identified by a distinctive site code
What is the MSSQL Primary database in SCCM?|The database that stores all data associated with the SCCM site, from user and machine information to client locations, applications, and more; it can reside on the Primary Server or a dedicated server
What is the SMS Provider in SCCM?|A component that facilitates communication between the SCCM service on the Primary Server and the primary MSSQL database, providing interfaces to deliver information to clients and enabling status communication
What is the Distribution Point (DP) in SCCM?|A service that ensures efficient distribution of applications, scripts, and other packages to logically grouped client machines
What is the Management Point (MP) in SCCM?|A service that orchestrates the transmission of various configurations from client machines to the Primary Server, ensuring smooth communication
What are secondary site servers in SCCM?|Optional servers with their own local database, often used by clients with limited bandwidth to offload the primary server and ensure optimum performance
What are passive site servers in SCCM?|Servers in highly available environments that are only activated if the Primary Server goes down
What are the six SCCM client deployment methods?|Client Push Installation (default), Software Update-Based Installation, Group Policy Installation, Manual Installation, Logon Script Installation, and Package and Program Installation
What are client push accounts in SCCM?|Service accounts with local administrative rights on the assets where SCCM will deploy components; one client push account per group of endpoints
What happens during SCCM Client Push Installation deployment?|SCCM tries to authenticate with each client push account on each asset; if authentication fails, it tries the next account; if no account works, the SCCM server tries its machine account as last resort
What is PXE (Pre-Boot Execution Environment)?|A mechanism for booting a computer over the network instead of from a CD drive, USB key, or hard disk; the PC uses the network to read the boot program from the PXE server
What UDP ports does a PXE server expose?|67, 68, 69, and 4011
What is PXEThief?|A Python tool used to query for PXE boot media through broadcast requests to request DHCP PXE boot options (only works on Windows due to pywin32 dependency)
What limitation does PXEThief have regarding registered machines?|It only works if attempting from a computer not registered on the SCCM server (categorized as Unknown) or if a particular configuration allows known clients to request PXE boot
What hashcat module is used to crack SCCM PXE media passwords?|Module 19850
What valuable information can be found in PXE media?|Credentials required to enroll new computers into the Active Directory domain, Network Access Account credentials, and task sequence credentials
What is sccmhunter?|A tool that can perform multiple attack and enumeration operations on SCCM, including enumeration and support for many attack scenarios
What information does sccmhunter extract from each SCCM server?|Site code, whether server is a CAS, SMB signing status, whether it's the Primary Server, Distribution Point, SMS Provider, and whether WSUS and MSSQL services are running
What three checks does the sccmhunter find command perform?|Checks DACL for System Management container, checks for published Management Points, and checks for strings SCCM and MECM in the entire directory
What Active Directory schema modifications does SCCM deployment create?|A new container named CN=System Management,CN=System and new LDAP object class entries such as mssmsmanagementpoint or mssmssite
What is SharpSCCM?|A C# tool for Windows systems that provides features for enumeration, credential gathering, and lateral movement without requiring access to the SCCM administration console
What are the three common places to search for SCCM credentials?|Device Collection Variables, Task Sequence Variables, and Network Access Accounts (NAAs)
What are Device Collection Variables in SCCM?|Key-value pairs associated with machine collections that store information referenced during deployments, which may contain sensitive identifiers or credentials
What are Task Sequence Variables in SCCM?|Steps configured to perform specific actions (like adding a machine to the domain) that can contain variables storing identifiers
What are Network Access Accounts (NAAs) in SCCM?|Domain accounts created to retrieve data from the Distribution Point when a machine cannot use its own account (e.g., when not yet enrolled in the domain); stored on disk encrypted by DPAPI
Why are NAA credentials potentially dangerous even after deletion?|Even after deleting or modifying the NAA identifiers, the binary file still contains the encrypted identifiers
How can NAAs be obtained without access to an already compromised machine?|By posing as a new machine on the network and requesting the SCCM policy
What sccmhunter options are available for extracting DPAPI secrets?|-wmi (extracts from WMI repository), -disk (extracts from OBJECTS.DATA on disk), or -both (combines both methods)
What is the Client Push Exploitation attack in SCCM?|An attack using the Heartbeat Discovery mechanism to fake DDR requests indicating absence of the SCCM client, causing the Primary Server to attempt authentication with each Client Push account
What are the prerequisites for Client Push Exploitation?|KB15599094 patch must not be applied, NTLM must not be manually disabled, HTTPS must not be used, and Client Push accounts must not use PKI certificate authentication
What is a DDR (Data Discovery Record) request?|A request used by the Heartbeat Discovery mechanism to update hardware inventories and client information by sending data to the Management Point
What tool is used for Client Push Exploitation from Windows?|SharpSCCM with the invoke client-push command, combined with Inveigh to capture the NTLM authentication
How can the SCCM site database be compromised via NTLM relay?|If the MSSQL database is on a separate server, the Primary Server machine account (which is local admin on the DB server) can be relayed to the database's SMB or MSSQL service
What two methods can be used to coerce SCCM server authentication for NTLM relay?|DDR enrollment requests to force the machine account, or traditional authentication coercion methods like PetitPotam or SpoolSample
What tables need to be modified to add an SCCM administrator via the database?|RBAC_Admins and RBAC_ExtendedPermissions tables in the CM_[SiteCode] database
What are the three Full Administrator role entries needed in RBAC_ExtendedPermissions?|SMS0001R RoleID with SMS00ALL scope (ScopeTypeID 29), SMS00001 scope (ScopeTypeID 1), and SMS00004 scope (ScopeTypeID 1)
How can the SMS Provider be attacked via NTLM relay?|By relaying the Primary Server's NTLM authentication to the AdminService REST API on the SMS Provider server to add a new administrator via the SMS_Admin WMI class
Why is the NTLM relay to SMS Provider particularly effective?|Because the HTTP service rarely checks NTLM signatures
How can a passive site server be exploited for NTLM relay?|Its machine account must be local admin on the active site server and all SCCM systems, so relaying its authentication to the active server's SMB service gives administrative access
What is CMPivot in SCCM?|A service on the Management Point server that can enumerate all resources of a computer or collection and perform administrative tasks, using the AdminService HTTP REST API
What can CMPivot enumerate on target computers?|Installed software, local administrators, hardware specifications, files and folders, and other resource information
What is the default restriction on script execution in SCCM?|An administrator cannot create and execute a script simultaneously; another administrator must validate the script before execution
How can the SCCM script approval restriction be bypassed?|By promoting a second user or computer account to Full Administrator and using it as an alternate approval account
What happens when an application deployment uses a UNC path pointing to the attacker's server?|The target machine attempts NTLM authentication against the attacker's share, allowing hash capture or NTLM relay
What authentication is received when deploying an application via SCCM with a UNC path?|Both the machine account and the NAA account attempt authentication since the machine account fails first
What are the key SCCM defensive recommendations for servers?|Install KB15599094, disable NTLM for client push, use Enhanced HTTP, disable automatic client push, set strong PXE passwords, require PKI certificates, avoid over-privileged credentials
What SCCM defensive measures should be taken for domain/server?|Require SMB signing on all site systems, enforce LDAP signing on domain controllers, require EPA on AD CS servers, disable SeMachineAccountPrivilege for non-admin users
What database defensive measure should be taken for SCCM?|Require Extended Protection for Authentication (EPA) on the site database, avoid linking other databases with DBA privileges, and set strong DBA passwords
What network defensive measures should be taken for SCCM?|Block unnecessary connections to site systems (especially SMB and MSSQL), only allow authorized administrators to support PXE boot on VLANs
What is Microsoft SQL Server (MSSQL Server)?|A proprietary relational database management system developed by Microsoft, the third most popular DBMS in the world
What is Transact-SQL (T-SQL)?|MSSQL Server's own dialect of SQL that extends capabilities by including procedural programming, local variables, support functions, and enhancements to DELETE and UPDATE statements
What is the difference between logins and users in MSSQL Server?|Logins are server-level security principals while users are database-level; one login can be mapped to multiple users across databases with a maximum of one user per database
What is the sa login in MSSQL Server?|The built-in sysadmin login, comparable to BUILTIN\Administrators; disabled by default when Windows Authentication Mode is selected during installation
What is a stored procedure in MSSQL Server?|Similar to a function that may accept input arguments, contain programming statements, and return a status value; MSSQL has many built-in stored procedures
What is an extended stored procedure in MSSQL Server?|A special type of stored procedure that allows MSSQL Server to execute native code stored in a DLL
What is the TRUSTWORTHY property in MSSQL Server?|A database property indicating whether the MSSQL Server instance should trust the database and its contents; off by default but can be enabled by sysadmin logins
What is the EXECUTE AS statement in MSSQL Server?|A statement that allows a login or user to switch the execution context to another login or user, essentially impersonating them until REVERT is called
How can IMPERSONATE permissions be exploited for privilege escalation?|If a login can impersonate sa or another sysadmin login, they can switch context and execute queries with sysadmin privileges
How can a trustworthy database be exploited for privilege escalation?|If a database is trustworthy and you control a db_owner user, you can create a stored procedure WITH EXECUTE AS OWNER to assign sysadmin role to arbitrary logins
What undocumented extended stored procedures can be used for UNC path injection?|xp_fileexist (checks file existence), xp_dirtree (returns directory tree), and xp_subdirs (returns sub-directories)
How does UNC path injection work in MSSQL Server?|By passing a UNC path to xp_dirtree/xp_fileexist/xp_subdirs pointing to an attacker's fake SMB share, the MSSQL service authenticates against it, revealing its NetNTLMv2 hash
What hashcat mode is used to crack NetNTLMv2 hashes?|Mode 5600
What user does the MSSQL Server service run as by default?|NT SERVICE\mssqlserver, but admins often change it to a domain user for interaction with other domain resources
What are three common ways to execute commands on MSSQL Server?|Using xp_cmdshell extended stored procedure, creating a malicious MSSQL Server Agent Job, and creating an OLE Automation stored procedure
What is xp_cmdshell?|A built-in extended stored procedure for command execution on MSSQL Server; disabled by default and requires show advanced options to be enabled first
How does xp_cmdshell execute commands?|It spawns a cmd.exe process as a child of sqlservr.exe with the command string as a command line argument
What subsystems are available for MSSQL Server Agent Job steps?|T-SQL, CmdExec, and PowerShell subsystems
What privilege does NT Service\sqlserveragent have by default?|SeImpersonatePrivilege, which can be exploited by "potato" attacks to escalate to SYSTEM
What are OLE Automation stored procedures?|Stored procedures using OLE Automation inter-process communication to use other languages like VBScript from T-SQL queries, using sp_OACreate and sp_OAMethod
What are linked servers in MSSQL Server?|A concept where server A is linked to server B, allowing remote execution of database queries on server B from server A with specified authentication credentials
What are the three ways to remotely execute queries on linked servers?|OPENQUERY (single result set on pre-defined linked server), EXECUTE AT (multiple result sets on pre-defined linked server), and OPENROWSET (ad-hoc connection with connection string)
How are linked server passwords encrypted and stored?|Encrypted with the Service Master Key using AES (since MSSQL 2012) or 3DES (before 2012), stored in the sys.syslnklgns table
What is required to access the sys.syslnklgns table?|A dedicated administrator connection (DAC), which by default may only be created locally
How is the Service Master Key protected?|Encrypted by DPAPI in both CurrentUser and LocalMachine contexts, stored in the sys.key_encryptions table with key_id 102
What three values are needed to decrypt linked server credentials with AES?|The Service Master Key (key), the first 16 bytes after padding of pwdhash (IV), and the remaining bytes of pwdhash (ciphertext)
What is Impacket MSSQLClient?|An open-source penetration testing tool from the Impacket project for connecting to and interacting with MSSQL Server instances, supporting MSSQL, Windows, and Kerberos authentication
What is PowerUpSQL?|A PowerShell toolkit by NetSPI for issuing T-SQL queries and automating MSSQL Server attacks including enumeration, privilege escalation, command execution, and lateral movement
What does Invoke-SQLAudit do?|Quickly identifies security issues with an MSSQL Server instance and provides exploitation information
What does Invoke-SQLEscalatePriv do?|Automatically escalates to sysadmin via vulnerabilities identified by Invoke-SQLAudit; permanently assigns sysadmin role to the authenticated login
What PowerUpSQL commands automate command execution?|Invoke-SQLOSCmd (xp_cmdshell), Invoke-SQLOSCmdAgentJob (Agent Jobs), and Invoke-SQLOSCmdOle (OLE Automation)
What does Get-SqlServerLinkCrawl do?|Enumerates linked servers and their links recursively, showing the path taken to reach each instance and what permissions are available
Why is Windows Authentication preferred over SQL Server Authentication?|It uses the Kerberos security protocol, has additional password policies, and makes user management simpler
What should defenders do about the public server role?|Not assign any additional privileges to the public server role, which is assigned by default to every login
Why should the BUILTIN\Administrators group have sysadmin revoked?|It's assigned by default during installation and is usually unnecessary; however attackers may still escalate from local admin to sysadmin
Why should serveradmin be treated the same as sysadmin?|Because escalation from serveradmin to sysadmin is trivial
Why should db_owner in a TRUSTWORTHY database be treated carefully?|Because db_owner can drop the database and can escalate to sysadmin if assigned to a TRUSTWORTHY database
What MSSQL configuration settings should defenders watch?|xp_cmdshell, Ole Automation Procedures, and clr enabled should remain disabled unless strictly necessary
How can xp_dirtree and similar procedures be restricted?|By revoking EXECUTE permissions from the public role, though testing in a non-production environment is recommended first
What default port does MSSQL Server use for TCP connections?|TCP port 1433
What is Microsoft Exchange?|A Microsoft product integrated into organizations for external and internal email communication, initially released in 1996, with currently supported versions 2016 and 2019
What communication clients/APIs does Exchange use?|Exchange Web Services (EWS), Outlook Web App (OWA), MAPI over HTTP, and ActiveSync (EAS)
What is AutoDiscover in Exchange?|A means for connection using only username and password to an Exchange server
What is the Global Address List (GAL)?|A catalog of the email addresses of users in Active Directory
What is Outlook Rules in Exchange?|A set of triggers running automatically based on different criteria
What is the expected login schema for Exchange?|DOMAIN\username format, where the domain and username depend on the organization's Active Directory configuration
What is the People view in Exchange?|A view that holds information about every user on the email server who can send/receive emails, including roles, phone numbers, and other details useful for phishing
What is usernameAnarchy?|A tool that creates username wordlists based on different formats from a list of names (first.last, flast, lastf, etc.)
How can the Global Address List be exported from Linux?|Using the global-address-list-owa Python script that connects to OWA and extracts all email addresses
How can the Global Address List be exported from Windows?|Using MailSniper's Get-GlobalAddressList function or PowerView
What is a password spray attack?|An attack involving a single password tested against multiple accounts, avoiding account lockouts that occur when multiple passwords are tried on a single account
What tools can perform password spray against Exchange?|Ruler, MailSniper (Invoke-PasswordSprayOWA/Invoke-PasswordSprayEWS), and Metasploit module scanner/HTTP/owa_login
How can you determine Exchange version?|By sending a GET request to /ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application and checking the version number in the response
What is ntlmscan?|A Python tool that performs checks on predefined endpoints to find those requiring NTLM authentication, useful for discovering autodiscover, EWS, and other Exchange endpoints
What is ProxyShell?|A chain of Exchange vulnerabilities discovered by Orange Tsai in 2021 allowing pre-auth remote code execution as NT AUTHORITY\SYSTEM without knowing email passwords
What three components make up ProxyShell?|Pre-auth Path Confusion, Exchange PowerShell Backend Elevation of Privilege, and Post-auth Arbitrary File Write
How does ProxyShell's pre-auth path confusion work?|Supplying a mailbox in the Email parameter of the URI exploits lack of input validation, allowing access to internal endpoints
How does ProxyShell achieve file write?|Using the New-MailboxExportRequest command's -FilePath parameter to export (write) an arbitrary webshell on disk in PST format
What Exchange versions are vulnerable to ProxyLogon (CVE-2021-26855)?|Exchange Server 2019 < 15.02.0792.010, 2019 < 15.02.0721.013, 2016 < 15.01.2106.013, and 2013 < 15.00.1497.012
What is ProxyLogon?|CVE-2021-26855, a vulnerability allowing unauthenticated command execution using Exchange's Proxy Architecture and Logon mechanism
How does phishing for NTLM hashes via email work?|Sending an email with a link to an SMB share causes Windows to automatically attempt authentication, allowing capture of the NTLMv2 hash
What conditions prevent SMB hash stealing via phishing emails?|Network not allowing outbound port 445, Outlook not automatically downloading images, or specific Outlook/Windows settings preventing SMB interactions
What is ntlm_theft?|An open-source tool that generates 21 types of hash theft documents for phishing when the target allows SMB traffic outside their network
What is an HTML Application (HTA)?|A Microsoft Windows program with source code consisting of HTML and scripting languages, executing as a fully trusted application without browser security model constraints, with .hta extension
What is HTML Smuggling?|A phishing technique where a legitimate-looking website automatically downloads malicious files to the victim's computer using JavaScript to decode and serve Base64-encoded payloads
What is CVE-2023-35636 in Exchange?|A vulnerability exploiting Calendar sharing capabilities to steal NTLM hashes from users
What is CVE-2023-23397 in Exchange?|A vulnerability that can steal NTLM hashes using the Reminder sound feature when creating an appointment
How can ProxyShell be detected?|Using YARA rules monitoring for the /autodiscover/autodiscover.json endpoint patterns, and checking for suspicious files in C:\inetpub\wwwroot\aspnet_client
What are Cumulative Updates (CU) in Exchange?|Quarterly updates from Microsoft that remediate vulnerabilities, separated into Security Updates (SU) and Hotfix Updates (HU)
What is evilginx?|A framework used by red team operators to mimic legitimate websites while relaying connections, used for phishing credential theft
What is ligolo-ng?|A tunneling tool with two components (agent and proxy) used for pivoting; the agent runs on the target Windows machine and the proxy on the attack host
What is Responder used for in Exchange attacks?|Capturing NTLM authentication attempts by running a fake SMB or HTTP server that prompts for or captures credentials
What is the AdminService API in SCCM?|A REST API that enables interaction with the SMS Provider and MSSQL database via standardized HTTP requests, integrated with the SMS_Admin WMI class
What is GadgetToJScript?|A tool that generates .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA scripts
What popular email security solutions exist?|Proofpoint, Microsoft Defender for Office 365, and Cisco Secure Email Threat Defense
What is Ruler?|A tool for interacting with Exchange servers remotely through MAPI/HTTP or RPC/HTTP protocol, supporting email discovery, password spray, rule manipulation, and shell access
What is MailSniper?|A PowerShell tool for Exchange enumeration, Global Address List extraction, and password spraying against OWA and EWS
What SCCM security monitoring should be implemented?|Monitor site system activity, watch for site system accounts authenticating from unexpected IPs, track client push installation accounts, use canary NAAs, and detect unusual application deployments
What is the SMS_Admin WMI class?|A WMI class integrated into the AdminService API that stores information about SCCM administrators and can be used to add new administrators
How does the sccmhunter http module work?|It spoofs standard client enrollment to recover Network Access Account credentials from discovered Management Points, automatically extracting and deobfuscating NAAs
What is addcomputer.py used for in SCCM attacks?|Creating a new computer account in the domain using Impacket when the domain policy permits it, which can then be used to request SCCM policies
What is Inveigh?|A .NET tool used to capture NTLM authentication requests on Windows, acting as a packet sniffer and responder for protocols like LLMNR, NBNS, and DNS
