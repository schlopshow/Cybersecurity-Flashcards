What is Active Directory (AD)?|A directory service for Windows network environments that provides a distributed, hierarchical structure for centralized management of an organization's resources including users, computers, groups, network devices, file shares, group policies, servers, workstations, and trusts
What two main functions does Active Directory provide within a Windows domain environment?|Authentication and authorization
When was Active Directory first released?|It was first shipped with Windows Server 2000
Why is Active Directory considered insecure by default?|It was designed to be backward-compatible, many features are not "secure by default," and it can be easily misconfigured
What can a basic AD user account with no added privileges enumerate?|Domain Computers, Domain Users, Domain Group Information, Default Domain Policy, Domain Functional Levels, Password Policy, Group Policy Objects (GPOs), Kerberos Delegation, Domain Trusts, and Access Control Lists (ACLs)
What common attacks leverage AD misconfigurations?|Kerberoasting/ASREPRoasting, NTLM Relaying, Network traffic poisoning, Password spraying, Kerberos delegation abuse, Domain trust abuse, Credential theft, and Object control
What is a forest in Active Directory?|The security boundary within which all objects are under administrative control; it may contain multiple domains and sits at the top of the AD hierarchy
What is a domain in Active Directory?|A structure within which contained objects (users, computers, and groups) are accessible
What are Organizational Units (OUs) in Active Directory?|Containers that may hold objects and sub-OUs, allowing for assignment of different group policies to maintain a clear and coherent structure within AD
What is the hierarchical structure of Active Directory?|A forest at the top containing one or more domains, which can contain nested subdomains; domains contain OUs which can contain objects and sub-OUs
What are the most basic units of data in Active Directory?|Objects
What key pieces of information should be gathered when starting AD enumeration?|Domain functional level, domain password policy, full inventory of AD users/computers/groups and memberships, domain trust relationships, object ACLs, GPO information, and remote access rights
What are "quick wins" to look for during AD enumeration?|Current user or Domain Users group having RDP and/or local administrator access to one or more hosts
Why is AD enumeration described as an iterative process?|As you move through the AD environment compromising hosts and users, additional enumeration is needed to see if further access has been gained
What is the Default Administrators group in AD?|Domain Admins and Enterprise Admins "super" groups
What can Server Operators group members do?|Modify services, access SMB shares, and backup files
Why should Backup Operators be considered Domain Admins?|They can log onto DCs locally, make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB
How can Print Operators be abused?|Members are allowed to log on to DCs locally and can "trick" Windows into loading a malicious driver
Why should Hyper-V Administrators be considered Domain Admins?|If there are virtual Domain Controllers, any virtualization admins such as Hyper-V Administrators effectively have Domain Admin level access
What can Account Operators do?|Modify non-protected accounts and groups in the domain
What is the significance of Remote Desktop Users group?|Members are not given useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using RDP
What can Remote Management Users do?|Log on to DCs with PSRemoting; this group is sometimes added to the local remote management group on non-DCs
What can Group Policy Creator Owners do?|Create new GPOs but would need additional delegated permissions to link GPOs to a container such as a domain or OU
What can Schema Admins do?|Modify the Active Directory schema structure and can backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL
How can DNS Admins group membership be abused?|Members can load a DLL on a DC (but can't restart DNS); they can load a malicious DLL and wait for a reboot, or create a WPAD record as a more reliable exploitation method
What is the difference between elevated and non-elevated user rights in Windows?|Non-elevated sessions show very limited privileges even for admin users, while elevated sessions show the complete listing of rights; this is controlled by User Account Control (UAC)
What privilege do Backup Operators have that could cause a massive service interruption?|SeShutdownPrivilege, which allows them to shut down a domain controller if they log on locally
What is RSAT (Remote Server Administration Tools)?|Tools that allow system administrators to remotely manage Windows Server roles and features from a workstation, including managing Active Directory, DNS, DHCP, and other server roles
What editions of Windows can RSAT be installed on?|Only Professional or Enterprise editions
What is the purpose of the "runas /netonly" command in AD enumeration?|It allows altering a user's context to enumerate AD using different credentials
What is NT AUTHORITY\SYSTEM?|A built-in account in Windows used by the service control manager with the highest level of access in the OS, more privileges than a local administrator account
What is the significance of SYSTEM access on a domain-joined host?|It is nearly equivalent to having a domain user account; the computer account can be used to enumerate Active Directory
What is the only real limitation of SYSTEM-level access in a domain context?|Not being able to perform cross-trust Kerberos attacks such as Kerberoasting
What are some ways to gain SYSTEM-level access on a host?|Remote Windows exploits (EternalBlue, BlueKeep), abusing services running as SYSTEM, abusing SeImpersonate privileges, local privilege escalation flaws, and PsExec with the -s flag
What can be done with SYSTEM-level access on a domain-joined host?|Enumerate domain data using BloodHound/PowerView, perform Kerberoasting/ASREPRoasting, run Inveigh for relay attacks, perform token impersonation, and carry out ACL attacks
What is LDAP?|Lightweight Directory Access Protocol - an open-source, cross-platform protocol used for authentication against directory services; it is the language applications use to communicate with directory servers like AD
How does an LDAP session begin?|By first connecting to an LDAP server (Directory System Agent); the Domain Controller actively listens for LDAP requests
How is the relationship between AD and LDAP analogous to web technology?|The same way Apache is a web server that uses HTTP, Active Directory is a directory server that uses the LDAP protocol
What are the two types of LDAP authentication?|Simple Authentication (anonymous, unauthenticated, or username/password creating a BIND request) and SASL Authentication (using other authentication services like Kerberos to bind to the LDAP server)
Why is SASL authentication more secure than Simple Authentication for LDAP?|SASL provides further security due to the separation of authentication methods from application protocols
Why should LDAP authentication be secured with TLS?|LDAP authentication messages are sent in cleartext by default, so anyone can sniff out LDAP messages on the internal network
What is a BIND operation in LDAP?|An operation used to set the authentication state for an LDAP session
What is AdminSDHolder in Active Directory?|An object owned by the Domain Admins group that has privileges to change permissions of objects in AD; groups with adminCount set to 1 are protected by it and known as protected groups
What does the DoesNotRequirePreAuth attribute indicate about a user?|The user can be ASREPRoasted - an attack that will be covered in Kerberos attack modules
What is a Service Principal Name (SPN) and why is it significant for attackers?|An SPN is an attribute set on service accounts; accounts with SPNs set can likely be subject to a Kerberoasting attack
What notation style do LDAP filter operators use?|Polish Notation - operators are placed in front of the criteria (operands)
What are the three LDAP filter comparison operators?|& (AND), | (OR), ! (NOT)
What are the LDAP search filter criteria rules?|Equal to (attribute=123), Not equal to (!(attribute=123)), Present (attribute=*), Not present (!(attribute=*)), Greater than (attribute>123), Less than (attribute<123), Approximate match (attribute~=123), and Wildcards (attribute=*A)
What is the OID 1.2.840.113556.1.4.803 (LDAP_MATCHING_RULE_BIT_AND)?|A matching rule where a match is found only if all bits from the attribute match the value, equivalent to a bitwise AND operator
What is the OID 1.2.840.113556.1.4.804 (LDAP_MATCHING_RULE_BIT_OR)?|A matching rule where a match is found if any bits from the attribute match the value, equivalent to a bitwise OR operator
What is the OID 1.2.840.113556.1.4.1941 (LDAP_MATCHING_RULE_IN_CHAIN)?|A special extended match operator limited to DN filters that walks the chain of ancestry in objects all the way to the root until it finds a match
What userAccountControl value represents an administratively disabled account?|2 (ACCOUNTDISABLE)
What userAccountControl value represents unconstrained delegation (trusted for delegation)?|524288
What does the PASSWD_NOTREQD flag (value 32) mean?|The account can have a blank password set
Why is it important to check for accounts with the PASSWD_NOTREQD flag?|Accounts without passwords are occasionally found; this can happen intentionally or accidentally when a user presses enter before typing a password
What is the RecursiveMatch parameter used for?|Finding all groups that a user is a member of, both directly and indirectly (nested group membership)
Why is enumerating nested group membership important?|A user may not be a direct member of a privileged group but could have derivative rights through nested group membership, which standard queries don't reveal
What are the three SearchScope levels in Active Directory?|Base (level 0 - the specified object itself), OneLevel (level 1 - objects in the container but not sub-containers), and SubTree (level 2 - objects in all child containers recursively)
What does the SearchBase parameter do?|Specifies an Active Directory path to search under, allowing searches to begin in a specific OU to improve performance and reduce results volume
What is the difference between the Filter parameter and the LDAPFilter parameter?|Filter uses PowerShell syntax with operators like -eq and -like, while LDAPFilter uses LDAP search filter syntax defined in RFC 4515
What are User-Account-Control (UAC) Attributes in AD?|Attributes that control the behavior of domain accounts (not to be confused with Windows UAC technology); many have security relevance such as PASSWD_NOTREQD, DONT_EXPIRE_PASSWORD, and DONT_REQ_PREAUTH
What is the NORMAL_ACCOUNT UAC flag value?|512
What is the DONT_EXPIRE_PASSWORD UAC flag value?|65536
What is the DONT_REQ_PREAUTH UAC flag value?|4194304
What built-in Windows tools can be used for AD enumeration?|DS Tools, PowerShell Active Directory module, Windows Management Instrumentation (WMI), and Active Directory Service Interfaces (ADSI)
What are DS Tools in Windows?|Built-in tools available by default on all modern Windows operating systems that require domain connectivity to perform AD enumeration activities
What is ADSI?|Active Directory Service Interfaces - a set of COM interfaces that can query Active Directory, accessible through PowerShell
What is an LDAP anonymous bind?|A configuration that allows unauthenticated attackers to retrieve information from the domain such as user listings, groups, computers, user account attributes, and the domain password policy
What types of servers commonly allow LDAP anonymous binds?|Linux hosts running open-source versions of LDAP and Linux vCenter appliances
What attacks can be mounted using information from an LDAP anonymous bind?|Password spraying attacks, AS-REPRoasting attacks, and reading information such as passwords stored in account description fields
What is windapsearch?|A Python script used to perform anonymous and authenticated LDAP enumeration of AD users, groups, and computers using LDAP queries
Why is it important to check user description fields during AD enumeration?|It is not uncommon to find passwords for users stored in the user description attribute in AD, which can be read by all AD users
What is the significance of unconstrained delegation in AD security?|Users or computers marked as trusted for unconstrained delegation can be exploited in Kerberos delegation attacks
What is Kerberoasting?|An attack targeting service accounts with Service Principal Names (SPNs) set, allowing attackers to request and attempt to crack their Kerberos tickets offline
What is ASREPRoasting?|An attack targeting accounts with the DoesNotRequirePreAuth attribute set, allowing attackers to request authentication data that can be cracked offline
What is the significance of the domain password policy in AD enumeration?|It reveals minimum password length, complexity requirements, and lockout thresholds, which inform password spraying attacks
Why is "offense in-depth" important in AD enumeration?|Knowledge of multiple tools is important in case you must live off the land on an assessment or detections are in place for certain tools
What is PowerView used for in AD enumeration?|It is a PowerShell tool for AD enumeration that can enumerate domain accounts, UAC values, group memberships, and other AD objects with built-in conversion of UAC flags
What is the purpose of proper AD hardening?|To prevent privilege escalation, lateral movement, and access to crown jewels even if an adversary gains a foothold; proper controls slow down attackers and force them to become noisier, risking detection
What information does the domain functional level reveal?|It indicates the minimum Windows Server version required for domain controllers, which determines available AD features and security capabilities
What is the relationship between a forest and domains in AD?|A forest is the top-level security boundary that can contain multiple domains; domains can contain child or sub-domains within the forest
Why can tools whitelisted for sysadmin use be valuable for attackers?|Tools like the PowerShell AD Module, Sysinternals Suite, and AD DS Tools are likely whitelisted and fly under the radar in mature environments, making them useful for living off the land
What is the significance of the adminCount attribute in AD?|Groups and users with adminCount set to 1 are protected by AdminSDHolder and are considered protected/administrative objects
What characters must be escaped when used in LDAP filters?|* (\2a), ( (\28), ) (\29), \ (\5c), and NUL (\00)
What are the four LDAP filter types?|Equal to (=), Approximately equal to (~=), Greater than or equal to (>=), and Less than or equal to (<=)
What are the four LDAP item types?|Simple (=), Present (=*), Substring (=something*), and Extensible (varies depending on type)
What is the purpose of the SearchScope Base level?|It queries the specified object itself; using it with Get-ADUser on an OU returns nothing, but using it with Get-ADObject returns the OU object
What is the purpose of the SearchScope OneLevel?|It searches for objects in the container defined by the SearchBase but not in any sub-containers
What is the purpose of the SearchScope SubTree?|It searches for objects contained by the SearchBase and all child containers, including their children, recursively all the way down the AD hierarchy
How can the LDAP_MATCHING_RULE_IN_CHAIN OID be used practically?|To find all groups that a user is a member of by walking the chain of ancestry, revealing both direct and nested group memberships
What is the significance of the servicePrincipalName attribute on administrative accounts?|Administrative accounts with SPNs are high-value targets for Kerberoasting since cracking their tickets yields privileged credentials
Why should organizations perform periodic account audits regarding the PASSWD_NOTREQD flag?|To ensure no accounts have blank passwords set, as the flag can be set intentionally or accidentally, creating a significant security risk
What is ldapsearch-ad.py?|A Python tool similar to windapsearch that can perform LDAP enumeration including built-in searches for password policies, Kerberoastable users, ASREPRoastable users, and domain information
What enumeration can be performed with credentialed LDAP access that anonymous access cannot?|More detailed information including Domain Admin enumeration, unconstrained delegation users/computers, fine-grained password policies, and comprehensive Kerberoasting/ASREPRoasting target identification
