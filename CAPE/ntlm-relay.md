What is privilege escalation in Active Directory?|The process of gaining higher-level permissions than currently assigned, moving from a standard user to Domain Admin or equivalent privileges
What are the two main types of privilege escalation?|Vertical (gaining higher privileges, e.g., standard user to admin) and Horizontal (gaining access to another account at the same privilege level but with different access)
What is an ACL (Access Control List)?|A list of Access Control Entries (ACEs) that define which security principals have specific permissions on an Active Directory object
What is the difference between DACL and SACL?|DACL (Discretionary ACL) defines who has access and what type; SACL (System ACL) defines what actions are audited and logged
What is an ACE (Access Control Entry)?|An individual permission entry within an ACL that specifies a trustee, an access right, and whether access is allowed or denied
What is the difference between Allow and Deny ACEs?|Deny ACEs take precedence over Allow ACEs; if both exist for the same permission, access is denied
What are the main ACL-based attack rights in Active Directory?|GenericAll, GenericWrite, WriteOwner, WriteDACL, ForceChangePassword, AddMember, ReadLAPSPassword, ReadGMSAPassword, and various Extended Rights
What does GenericAll permission allow?|Full control over an object - equivalent to combining all other permissions; allows password resets, group membership changes, Kerberos delegation settings, and more
What does GenericWrite permission allow?|Writing to any non-protected attribute of an object, including adding SPNs for Kerberoasting, modifying logon scripts, or changing group membership
What does WriteOwner permission allow?|Changing the owner of an object to a controlled principal, after which the new owner can grant themselves any permission via WriteDACL
What does WriteDACL permission allow?|Modifying the DACL on an object, enabling the attacker to grant themselves or others any permissions on that object
What does ForceChangePassword allow?|Resetting the password of a target user without knowing the current password, using the Set-ADAccountPassword or net user command
What is the AddMember right?|Permission to add members to a group, such as adding a controlled user to a privileged group like Domain Admins
What are Extended Rights in Active Directory?|Special permissions for specific operations not covered by standard read/write permissions, including User-Force-Change-Password and DS-Replication-Get-Changes
What tools can enumerate ACL misconfigurations?|BloodHound/SharpHound (graph-based analysis), PowerView (PowerShell enumeration), ADACLScanner (GUI/report-based), and Impacket dacledit (Linux-based)
What is BloodHound used for in ACL attacks?|Mapping relationships and permissions in AD to find attack paths from controlled principals to high-value targets like Domain Admins
What is Kerberos Delegation?|A feature allowing a service to impersonate a user and access other services on their behalf, using the user's credentials
What are the three types of Kerberos Delegation?|Unconstrained Delegation, Constrained Delegation, and Resource-Based Constrained Delegation (RBCD)
What is Unconstrained Delegation?|A delegation type where the service can impersonate the user to any service; the user's TGT is stored in the service's memory for reuse
Why is Unconstrained Delegation dangerous?|Because any user authenticating to the service leaves their TGT cached in memory, which can be extracted and used to impersonate that user to any service
How can Unconstrained Delegation be exploited?|By coercing a privileged account (like a Domain Controller) to authenticate to the compromised service, then extracting the cached TGT to impersonate that account
What is the Printer Bug (SpoolSample)?|A technique that coerces a remote host to authenticate back to an attacker-controlled host using the MS-RPRN Print Spooler service
What is Constrained Delegation?|A delegation type that limits which services a principal can delegate credentials to, using a list of allowed SPNs stored in the msDS-AllowedToDelegateTo attribute
What are the two Kerberos extensions used in Constrained Delegation?|S4U2Self (Service for User to Self - obtains a service ticket for the service itself on behalf of a user) and S4U2Proxy (uses the ticket from S4U2Self to request a ticket for the allowed target service)
What is the difference between Constrained Delegation with and without Protocol Transition?|With Protocol Transition (TrustedToAuthForDelegation), S4U2Self returns a forwardable ticket allowing any user impersonation; without it, the ticket is non-forwardable and requires the user to first authenticate via Kerberos
What is Resource-Based Constrained Delegation (RBCD)?|A delegation type where the target resource controls who can delegate to it via the msDS-AllowedToActOnBehalfOfOtherIdentity attribute, rather than the delegating service controlling it
What permission is needed to configure RBCD on a target?|Write permission to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the target computer object (GenericAll, GenericWrite, or WriteProperty on that attribute)
How is RBCD typically exploited?|By writing a controlled computer account's SID into the target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute, then using S4U2Self and S4U2Proxy to obtain tickets for the target as any user
What is the Machine Account Quota (MAQ)?|The ms-DS-MachineAccountQuota attribute that defines how many computer accounts a user can create in the domain (default is 10)
Why is the Machine Account Quota relevant to RBCD attacks?|Because creating a computer account gives you a controlled principal with an SPN that can be used as the delegating service in RBCD attacks
What is GPO (Group Policy Object) abuse?|Exploiting write permissions on Group Policy Objects to push malicious configurations, scripts, or scheduled tasks to all computers and users in the GPO's scope
What can an attacker do with write access to a GPO?|Add scheduled tasks, modify security settings, deploy software, change registry keys, add logon/startup scripts, or modify user rights assignments
What tools can abuse GPO permissions?|SharpGPOAbuse (adds immediate scheduled tasks, logon scripts, etc.) and pyGPOAbuse (Python equivalent from Linux)
What are Organizational Units (OUs)?|Containers in Active Directory used to organize objects (users, computers, groups) and apply Group Policy Objects for centralized management
Why is OU structure important for GPO attacks?|Because GPOs linked to an OU affect all objects within it, so compromising a GPO linked to a high-value OU can compromise all objects in that OU
What is GPO Inheritance?|The mechanism where GPOs applied to parent OUs are inherited by child OUs, unless inheritance is blocked
What is the "Enforce" (No Override) setting on GPOs?|A setting that ensures a GPO's settings are applied even if a child OU blocks inheritance
What is LAPS (Local Administrator Password Solution)?|A Microsoft solution that automatically manages and rotates local administrator passwords for domain-joined computers, storing them in Active Directory
Where are LAPS passwords stored?|In the ms-Mcs-AdmPwd attribute (Legacy LAPS) or msLAPS-Password/msLAPS-EncryptedPassword attributes (Windows LAPS) on computer objects in Active Directory
Who can read LAPS passwords by default?|Domain Admins and any users or groups explicitly granted read permissions on the LAPS attributes through ACLs
What is Windows LAPS vs Legacy LAPS?|Windows LAPS is built into Windows (April 2023+) with features like encrypted passwords and Azure AD support; Legacy LAPS is the older downloadable solution using plaintext storage in ms-Mcs-AdmPwd
What tools can read LAPS passwords?|LAPSToolkit (PowerShell), NetExec/CrackMapExec (with --laps flag), ldapsearch, Get-ADComputer with LAPS properties, and the LAPS UI
What is the LAPS password expiration attribute?|ms-Mcs-AdmPwdExpirationTime - stores when the LAPS password will be automatically rotated; modifying this can force or prevent password rotation
What is Group Managed Service Account (gMSA) password abuse?|Extracting gMSA passwords by reading the msDS-ManagedPassword attribute when you have the PrincipalsAllowedToRetrieveManagedPassword right
How are gMSA passwords generated?|Automatically by Active Directory using the KDS Root Key, rotated every 30 days by default, with passwords being 256 bytes (120+ characters)
What is AS-REP Roasting?|An attack targeting accounts with Kerberos pre-authentication disabled, allowing anyone to request an AS-REP containing data encrypted with the user's password hash for offline cracking
What is the DONT_REQUIRE_PREAUTH flag?|A user account control flag that disables Kerberos pre-authentication, making the account vulnerable to AS-REP Roasting
What Hashcat mode is used for AS-REP Roasting?|Mode 18200 for Kerberos 5 AS-REP etype 23
What is Kerberoasting?|An attack that requests TGS tickets for service accounts with SPNs, then cracks the tickets offline since part of the ticket is encrypted with the service account's NTLM hash
Why are service accounts good Kerberoasting targets?|Because they often have weak passwords, have high privileges, and their password hashes are used to encrypt TGS tickets that anyone with a valid domain account can request
What Hashcat mode is used for Kerberoasting?|Mode 13100 for Kerberos 5 TGS-REP etype 23
What is Targeted Kerberoasting?|Setting an SPN on a user account you have GenericWrite or GenericAll permissions over, then Kerberoasting that account to crack its password
What is Shadow Credentials?|An attack that abuses the msDS-KeyCredentialLink attribute to add alternative credentials (public key) to a target object, enabling PKINIT authentication without knowing the password
What attribute is used in Shadow Credentials attacks?|msDS-KeyCredentialLink - stores the public key portion of a key pair that can be used for PKINIT pre-authentication
What prerequisites are needed for Shadow Credentials attacks?|AD CS or a Key Trust setup, Windows Server 2016+ Domain Controller, and write permission to the target's msDS-KeyCredentialLink attribute
What tool is used for Shadow Credentials attacks on Windows?|Whisker - adds a new key credential, generates a certificate, and provides a Rubeus command to obtain a TGT
What tool is used for Shadow Credentials attacks on Linux?|pyWhisker - the Python equivalent of Whisker
What is DCSync?|A technique that uses replication rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) to simulate a Domain Controller and extract password hashes from Active Directory
What accounts have DCSync rights by default?|Domain Admins, Enterprise Admins, the Domain Controllers group, and the Administrators group
What is the difference between DCSync and NTDS.dit extraction?|DCSync uses replication protocol remotely without needing to be on the DC; NTDS.dit extraction requires local access to the Domain Controller to copy and parse the database file
What is AD CS (Active Directory Certificate Services)?|A server role that provides public key infrastructure (PKI) functionality, issuing digital certificates for authentication, encryption, and digital signatures
What is ESC1 in AD CS attacks?|A misconfigured certificate template that allows a low-privileged user to specify an arbitrary Subject Alternative Name (SAN), enabling authentication as any user including Domain Admins
What three conditions make a template vulnerable to ESC1?|Enrollee supplies the subject name (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT), Client Authentication EKU is enabled, and low-privileged users have enrollment rights
What is ESC2?|A template with the Any Purpose EKU or no EKU (SubCA), which can be used for any purpose including client authentication
What is ESC3?|A misconfiguration involving an enrollment agent certificate template that allows requesting certificates on behalf of other users
What is ESC4?|Vulnerable access control on certificate templates, where a user with write access can modify the template to make it vulnerable to ESC1
What is ESC6?|When the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on the CA, allowing any certificate request to specify an arbitrary SAN regardless of template settings
What is ESC7?|When a user has ManageCA or ManageCertificates rights on the CA, allowing them to approve pending certificate requests or modify CA configuration
What is ESC8?|The HTTP-based enrollment endpoint (NTLM Relay to AD CS) vulnerability where NTLM authentication to the enrollment web service can be relayed to request certificates
What is ESC11?|NTLM relay to the AD CS RPC enrollment interface (ICertPassage) when the CA does not enforce IF_ENFORCEENCRYPTICERTREQUEST
What is Certifried (CVE-2022-26923)?|A vulnerability where a computer account's dNSHostName can be modified to match a Domain Controller's, then a machine certificate is requested and used to authenticate as the DC
What tool is used for AD CS enumeration and exploitation?|Certipy (Python, Linux-based) and Certify (C#, Windows-based)
What is the YOUREXPLOIT concept in privilege escalation?|A reminder that novel attack paths and misconfigurations always exist beyond documented techniques, emphasizing creative thinking and thorough enumeration
What is Token Impersonation?|Exploiting Windows access tokens to assume the identity of another user, typically using SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
What privileges are needed for Token Impersonation attacks?|SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege, commonly held by service accounts and IIS application pool identities
What are Potato attacks?|A family of privilege escalation techniques (Hot Potato, Rotten Potato, Juicy Potato, Sweet Potato, PrintSpoofer, GodPotato) that abuse token impersonation to escalate from service account to SYSTEM
What is PrintSpoofer?|A privilege escalation tool that abuses the SpoolSS service to capture a SYSTEM token when the attacker has SeImpersonatePrivilege
What is the difference between PrintSpoofer and Potato attacks?|PrintSpoofer abuses the Print Spooler named pipe, while Potato attacks abuse various DCOM/RPC/BITS mechanisms, but all require SeImpersonatePrivilege and aim to get SYSTEM
What is DNSAdmins abuse?|A privilege escalation technique where members of the DNSAdmins group can load an arbitrary DLL into the DNS service (which runs as SYSTEM on Domain Controllers)
How does DNSAdmins privilege escalation work?|By configuring the DNS service to load a malicious DLL from a network share using the ServerLevelPluginDll registry entry, then restarting the DNS service
What is the Backup Operators group escalation?|Members can backup the NTDS.dit file and SYSTEM registry hive from a Domain Controller, then extract password hashes offline
What is the Server Operators group escalation?|Members can start/stop services on Domain Controllers, allowing them to modify a service binary path to execute arbitrary commands as SYSTEM
What is the Account Operators group escalation?|Members can create and modify most user and group accounts (except protected ones), potentially creating accounts or modifying group memberships for further access
What is Exchange Windows Permissions group abuse?|Members have WriteDACL on the domain object by default, allowing them to grant themselves DCSync rights
What is the Certificate Service DCOM Access group?|A group that can interact with AD CS DCOM interfaces, potentially useful for certificate enrollment attacks
What is the Pre-Windows 2000 Compatible Access group?|A group that provides read access to many AD attributes for backward compatibility, sometimes including sensitive information
What is the Print Operators group escalation?|Members can load printer drivers on Domain Controllers, which can be exploited to load malicious kernel-mode drivers
What is trust abuse in Active Directory?|Exploiting trust relationships between domains or forests to escalate privileges or move laterally across trust boundaries
What are the two main types of AD trusts?|Intra-forest trusts (within the same forest, implicit two-way transitive trust) and Inter-forest trusts (between different forests, can be one-way or two-way)
What is SID Filtering?|A security mechanism that removes SIDs from other domains in authentication tokens when crossing trust boundaries, preventing SID History abuse across forest trusts
What is Selective Authentication in trusts?|A trust setting that restricts which users from the trusted domain can authenticate to resources in the trusting domain, providing more granular access control
What is the ExtraSids attack?|Forging a Golden Ticket with additional SIDs (like Enterprise Admins SID) in the ticket's ExtraSids field to gain access across domain trusts within a forest
Why does the ExtraSids attack work within a forest?|Because intra-forest trusts don't apply SID Filtering, so the forged SIDs in the ticket are accepted by other domains in the same forest
What is the Trust Ticket (Inter-Realm TGT) attack?|Forging a TGT using the inter-realm trust key (the shared secret between two domains) to create tickets accepted by the target domain
What is PAM Trust (Privileged Access Management)?|A forest trust feature in Windows Server 2016+ that creates a bastion forest for managing privileged access, using shadow principals and time-limited group membership
What is the krbtgt/domain account in trust attacks?|The trust account whose hash is used to encrypt inter-realm TGTs; compromising this hash allows forging trust tickets
What are the key defenses against Kerberos delegation attacks?|Mark sensitive accounts as "Account is sensitive and cannot be delegated," use Protected Users group, implement tiered administration, monitor delegation configurations, and prefer RBCD over unconstrained delegation
What is the Protected Users group?|A security group where members cannot use NTLM authentication, Kerberos delegation, or CredSSP; their TGT lifetime is limited to 4 hours
What is the "Account is sensitive and cannot be delegated" flag?|A user account property that prevents the account's credentials from being delegated through any delegation mechanism, protecting against delegation-based attacks
What is the tiered administration model?|A security model that separates administrative privileges into tiers (Tier 0 for domain controllers and AD, Tier 1 for servers, Tier 2 for workstations) to limit lateral movement and privilege escalation
What is the general methodology for AD privilege escalation?|Enumerate (BloodHound, PowerView), identify misconfigurations (ACLs, delegation, templates), exploit the weakest path, escalate iteratively, and aim for Domain Admin or equivalent
Why should you enumerate before exploiting in AD?|Because AD environments are complex with many interconnected objects and permissions; thorough enumeration often reveals easier or less detectable paths to privilege escalation
What makes AD CS particularly dangerous for privilege escalation?|Certificate templates persist across the environment, certificates are valid for extended periods (often 1+ years), and misconfigured templates can allow any user to authenticate as Domain Admin
What is S4U2Self?|Service for User to Self - a Kerberos extension that allows a service to obtain a service ticket to itself on behalf of any user, even if that user hasn't authenticated to the service
What is S4U2Proxy?|Service for User to Proxy - a Kerberos extension that allows a service to use a user's service ticket to request tickets for other services the delegation is configured to access
What is the ms-DS-MachineAccountQuota default value?|10 - meaning by default, any authenticated domain user can create up to 10 computer accounts in the domain
What is the significance of SPN (Service Principal Name) in attacks?|SPNs are used for Kerberoasting (accounts with SPNs can have their TGS tickets requested and cracked) and for delegation configuration (specifying which services can be delegated to)
What is PKINIT?|Public Key Cryptography for Initial Authentication in Kerberos - allows authentication using certificates instead of passwords, abused in Shadow Credentials and AD CS attacks
What is the msDS-AllowedToDelegateTo attribute?|An attribute on a principal that lists the SPNs of services it is allowed to delegate credentials to under Constrained Delegation
What is the msDS-AllowedToActOnBehalfOfOtherIdentity attribute?|An attribute on a target resource that specifies which principals are allowed to delegate to it under Resource-Based Constrained Delegation
What is the TrustedToAuthForDelegation flag?|A flag on a service account that enables Protocol Transition in Constrained Delegation, allowing S4U2Self to produce forwardable tickets for any user
What does the TRUSTED_FOR_DELEGATION flag indicate?|That the account is configured for Unconstrained Delegation and will cache TGTs of authenticating users in its memory
What is certificate template enrollment rights?|ACL permissions (typically Enroll or AutoEnroll) that determine which users or groups can request certificates from a specific template
What is the Subject Alternative Name (SAN) in AD CS?|A certificate field that can contain alternative identities (like a different user's UPN); when enrollees can specify the SAN, they can authenticate as any user
What Event IDs are useful for detecting privilege escalation?|4672 (special privileges assigned), 4728/4732/4756 (member added to security groups), 4768/4769 (Kerberos ticket requests), 5136 (directory object modified)
Why is BloodHound critical for AD privilege escalation?|It maps the entire AD environment's relationships and permissions into a graph database, automatically finding attack paths from any controlled principal to high-value targets that would be nearly impossible to find manually
