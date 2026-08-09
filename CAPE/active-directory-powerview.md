What is PowerView?|A PowerShell tool contained within the PowerSploit offensive toolkit used to gain situational awareness in Active Directory by utilizing PowerShell AD hooks and Win32 API functions; it replaces various Windows net commands
What is SharpView?|A .NET port of PowerView that provides all PowerView functions and arguments in a .NET assembly, designed for C# inline tradecraft which is less security transparent than PowerShell
Why was offensive tooling ported from PowerShell to C#?|PowerShell has become more security transparent with better detection optics available for both consumer and enterprise-level endpoint protection products, so practitioners evolved to C# which is less security transparent
What is a major difference between PowerView and SharpView regarding output handling?|SharpView uses strings instead of PowerShell objects, so you cannot specify properties using Select or Select-Object to parse output or select specific AD objects as easily
What is BloodHound used for?|Visually mapping out AD relationships and planning attack paths that may otherwise go unnoticed; it uses SharpHound C# ingestor to gather data imported into a JavaScript application with Neo4j database for graphical analysis
What is BloodHound.py?|A Python-based BloodHound ingestor based on the Impacket toolkit that supports most collection methods and can be run from a non-domain joined attack box
What is CrackMapExec (CME)?|An enumeration, attack, and post-exploitation toolkit that attempts to "live off the land" and abuse built-in AD features and protocols such as SMB, WMI, WinRM, and more
What is PingCastle used for?|Auditing the security level of an AD environment based on a risk assessment and maturity framework based on CMMI adapted to AD security
What is Snaffler used for?|Finding information such as credentials in Active Directory on computers with accessible file shares
What is Group3r used for?|Auditing and finding security misconfigurations in AD Group Policy Objects (GPOs)
What is MailSniper used for?|Searching through email inboxes in a Microsoft Exchange environment for specific keywords/terms that may reveal sensitive data for lateral movement and privilege escalation; also used for password spraying and enumerating domain users
What is ADRecon?|A tool used to extract various data from a target AD environment and output it in Microsoft Excel format with summary views and analysis
What is Active Directory Explorer?|An AD viewer and editor that can navigate an AD database, view object properties and attributes, save snapshots for offline analysis, and compare two snapshots to see changes
What is windapsearch?|A Python script used to enumerate AD users, groups, and computers using LDAP queries, useful for automating custom LDAP queries
What is PowerUpSQL used for?|SQL Server discovery, configuration auditing, privilege escalation, and post-exploitation
What are the functional categories of PowerView/SharpView?|Misc Functions, Domain/LDAP Functions, GPO Functions, Computer Enumeration Functions, Threaded Meta-Functions, and Domain Trust Functions
What does the ConvertTo-SID function do?|Converts a given user/group name to a security identifier (SID)
What does the Convert-ADName function do?|Converts object names between a variety of formats, including converting SIDs back to usernames
What does the ConvertFrom-UACValue function do?|Converts a UAC integer value to human-readable form; with the -showall property, all common UAC values are shown with set ones marked with a +
What does the Invoke-Kerberoast function do?|Requests service tickets for Kerberoast-able accounts and returns extracted ticket hashes
What does the Get-DomainSPNTicket function do?|Requests the Kerberos ticket for a specified service principal name (SPN)
What does Get-Domain return?|Information about the domain such as name, child domains, list of domain controllers, domain controller roles, and more
What does Get-DomainOU do?|Searches for all organization units (OUs) or specific OU objects in AD, helping map out the domain structure
What does Get-DomainUser do?|Returns all users or specific user objects in AD with various properties like group membership, account settings, and delegation status
What key user properties should be gathered during AD enumeration?|name, samaccountname, description, memberof, whencreated, pwdlastset, lastlogontimestamp, accountexpires, admincount, userprincipalname, serviceprincipalname, mail, and useraccountcontrol
Why is it useful to export all domain user properties to CSV?|For offline processing, allowing thorough analysis of user data without repeated queries to the domain controller
What does the KerberosPreauthNotRequired parameter filter for?|User accounts that do not require Kerberos pre-authentication, making them susceptible to ASREPRoasting attacks
What does the TrustedToAuth parameter filter for?|Users that are trusted to authenticate for other principals, indicating Kerberos constrained delegation configuration
What does the SPN parameter filter for in Get-DomainUser?|Users with non-null Service Principal Names set, making them potential targets for Kerberoasting attacks
Why is checking user description fields important during enumeration?|Passwords are sometimes stored in the description field of user accounts in AD, which can be read by all domain users
What does Find-ForeignGroup do?|Identifies users from other (foreign) domains that have group membership within groups in the current domain
Why is finding foreign group members significant?|If you compromise the current domain, you may obtain credentials for foreign users from the NTDS database and authenticate into the foreign domain
What is the significance of Kerberoasting across trust relationships?|Users with SPNs in other domains that can be authenticated to via trust relationships can be targeted for Kerberoasting across forest trusts
Why are password set times important for password spraying?|They reveal patterns like help desk bulk resets (likely same password), seasonal password choices, old weak passwords, and administrators likely reusing passwords across multiple accounts
What do multiple passwords set at the same time indicate?|They were likely set by the Help Desk and may be the same password across all affected accounts
How can old password set dates inform password guessing?|Passwords set years ago are likely weak and should be prioritized for guessing; the date also helps exclude unlikely password variations
Why should you check if an administrator changed both their user and admin accounts around the same time?|They are highly likely to use the same password for both accounts
What does Get-DomainGroupMember do?|Returns the members of a specific domain group, showing member details like name, SID, and distinguished name
What are protected groups in AD?|Groups with the AdminCount attribute set to 1, which are protected by AdminSDHolder
What are managed security groups?|Groups that have delegated non-administrators the right to add members by modifying the managedBy attribute; the manager may have GenericWrite privileges to modify group membership
What does Find-ManagedSecurityGroups reveal?|Groups that have a manager set, which could be useful for lateral movement if the manager account is compromised and can add users to the group
Why is local group membership enumeration important?|To determine if the current user is a local admin or part of local groups on any hosts, which enables lateral movement
What does Test-AdminAccess do?|Tests if the current user has administrative access to the local or a remote machine
What does Find-DomainUserLocation do?|Finds domain machines where specific users are logged in, useful for targeting specific users
What does Find-LocalAdminAccess do?|Finds machines on the local domain where the current user has local administrator access
What does Find-InterestingDomainShareFile do?|Searches for files matching specific criteria on readable shares in the domain
What is the Get-ADGroupMemberDate module used for?|Pulling the date when a user was added to a group, useful for incident response to search for related Event IDs on that date
What Event IDs relate to group membership changes?|Event ID 4728/4738 for when a user was added to a group, and Event ID 4624 to see if anyone has logged in since the date added
What are the two types of ACLs in Active Directory?|Discretionary Access Control List (DACL) which defines granted or denied access, and System Access Control List (SACL) which allows administrators to log access attempts
What are Access Control Entries (ACEs)?|The individual settings within an ACL that refer back to a user, group, or process (security principal) and define that principal's rights
What are "derivative admins" in AD?|Users who can derive admin rights from exploiting an AD attack chain through unrolled membership of target groups, even though they are not directly privileged
What AD attack chain components can ACL misconfigurations enable?|Shadow admins having access on member servers, privileged users with sessions on compromised workstations, and object-to-object control like force password change, add group member, change owner, write ACE, and full control
What are the key abusable AD object security permissions?|ForceChangePassword, Add Members, GenericAll, GenericWrite, WriteOwner, WriteDACL, and AllExtendedRights
How can ForceChangePassword be abused?|Using Set-DomainUserPassword to forcefully change a target user's password
How can GenericAll be abused?|Using Set-DomainUserPassword or Add-DomainGroupMember to change passwords or add group members
How can GenericWrite be abused?|Using Set-DomainObject to modify object properties, or setting a fake SPN for targeted Kerberoasting, or modifying userAccountControl for targeted ASREPRoasting
How can WriteOwner be abused?|Using Set-DomainObjectOwner to take ownership of an object
How can WriteDACL be abused?|Using Add-DomainObjectACL to add new ACL entries, such as granting Replicating Directory Changes permissions for a DCSync attack
How can AllExtendedRights be abused?|Using Set-DomainUserPassword or Add-DomainGroupMember
What is a DCSync attack?|An attack requiring Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes In Filtered Set rights, allowing an attacker to mimic a Domain Controller to retrieve user NTLM password hashes
What does Find-InterestingDomainAcl do?|Searches for objects in the domain with modification rights set to non-built-in objects, revealing potential ACL misconfigurations
Why should file share ACLs be enumerated?|To identify overly permissive shares that could lead to sensitive data disclosure or other attacks
How can WriteDacl over the domain object lead to full compromise?|By granting an account Replicating Directory Changes and Replicating Directory Change permissions, enabling a DCSync attack to retrieve NTLM password hashes for any account
What is a less destructive alternative to changing a user's password when you have GenericAll/GenericWrite?|Setting a fake SPN on the account for targeted Kerberoasting or modifying userAccountControl to not require Kerberos pre-authentication for targeted ASREPRoasting
What attack can be performed with GenericAll/GenericWrite over a computer object?|A Kerberos Resource-based Constrained Delegation attack
What can be done if Domain Users group has write permissions over a GPO?|Use SharpGPOAbuse to modify the GPO to provision additional privileges, add local admin, add startup scripts, and more
How can you revert a password change after a destructive action like password reset?|DCSync to obtain the account's password history, then use Mimikatz LSADUMP::ChangeNTLM or LSADUMP::SetNTLM to reset to the previous password
What is a Group Policy Object (GPO)?|A collection of policy settings that provides centralized management of configuration settings for operating systems, user and computer settings in a Windows environment
What types of attacks can be performed through GPO abuse?|Adding additional rights to a user, adding a local admin, creating immediate scheduled tasks, modifying group membership, running DCSync, installing malware across the domain
What is SharpGPOAbuse?|A tool used to take advantage of GPO misconfigurations, supporting attacks like AddUserRights and AddLocalAdmin
What are the hidden GPO code execution paths that should be checked?|Add Registry Autoruns, Software Installation (MSI on share), Scripts in Startup/Shutdown, Create Shortcuts pointing to files, and Scheduled Tasks
Why should you check executables referenced by GPOs, not just GPO permissions?|Tools often only check if the Group Policy itself is writable, but the executables or scripts the GP references may also be writable by non-administrators
What commercial applications do organizations commonly use instead of GPO for configuration management?|Microsoft SCCM, PDQInventory/Deploy, NinjaRMM, and Ansible/Puppet/Salt
What information can GPO names reveal about domain security?|Security configurations like LAPS deployment, AppLocker, PowerShell Logging, disabled cmd.exe, disabled SMBv1, audit policies, and other security controls
What is a trust in Active Directory?|A link between authentication systems of two domains that allows users to access resources in or administer another domain outside their own
What is a transitive trust?|A trust that is extended to objects which the child domain trusts, creating a chain of trust relationships
What is a non-transitive trust?|A trust where only the child domain itself is trusted, not extending to other domains
What is a bidirectional trust?|A trust where users from both trusting domains can access resources in either domain
What is a one-way trust?|A trust where only users in the trusted domain can access resources in the trusting domain; the direction of trust is opposite to the direction of access
What is a Parent-child trust?|A two-way transitive trust between domains within the same forest, where the child domain automatically trusts the parent
What is a Cross-link trust?|A trust between child domains created to speed up authentication
What is an External trust?|A non-transitive trust between two separate domains in separate forests not joined by a forest trust, utilizing SID filtering
What is a Tree-root trust?|A two-way transitive trust between a forest root domain and a new tree root domain, created by design when setting up a new tree root domain
What is a Forest trust?|A transitive trust between two forest root domains
Why are domain trusts a security concern?|They are often set up improperly providing unintended attack paths, may not be reviewed for security implications, and M&A can introduce bidirectional trusts that create risk in the acquiring company's environment
What does Get-DomainTrust return?|All domain trusts for the current domain, including source/target names, trust type, attributes, direction, and creation dates
What does Get-DomainTrustMapping do?|Enumerates all trusts for the current domain and then enumerates all trusts for each domain it finds, providing a complete trust map
What is the ExtraSids attack?|An attack that allows compromising a parent domain once a child domain has been compromised, possible because the sidHistory property is respected due to lack of SID Filtering protection
What is the SID History attribute used for?|In migration scenarios, the original user's SID is added to the new user's SID History attribute, ensuring they can still access resources in the original domain
How can SID History be abused within the same domain?|Using Mimikatz to perform SID History injection, adding a Domain Admin SID to the SID History of a controlled account, which then allows DCSync and golden ticket creation
How can SID History be abused across a forest trust?|If SID Filtering is not enabled, a SID from the other forest can be added to an account's SID History, granting administrative privileges when accessing resources in the partner forest
What is SID Filtering?|A security mechanism used on external trusts that prevents SID History abuse by filtering out SIDs from other domains
What common way exists to cross trust boundaries besides trust attacks?|Password re-use - administrators often reuse passwords across environments, so credentials found in one forest may work in a trusted forest
Why should you check for foreign users and foreign group membership?|Accounts belonging to groups in one forest may actually be part of another forest and can be used to gain a foothold in the partner forest
What attacks can be performed across bidirectional parent-child trusts?|Kerberoasting, ASREPRoasting in either direction, and ExtraSids attack from child to parent domain
What attacks can be performed across bidirectional forest trusts?|Kerberoasting, ASREPRoasting, and potentially SID History abuse if SID Filtering is not enabled
Why might organizations establish domain trusts?|Regional management separation, quick integration during acquisitions, logical separation of development/testing environments, and minimizing the number of accounts required
What is the risk of trusts established during mergers and acquisitions?|The acquired company may have legacy hosts, no regular security assessments, different or no security monitoring controls, creating risk in the acquiring company's environment
What does the WITHIN_FOREST trust attribute indicate?|The trust is between domains within the same Active Directory forest
What does the FOREST_TRANSITIVE trust attribute indicate?|The trust is between two separate forests and is transitive
What Exchange groups are considered high-value targets due to their permissions?|Exchange Trusted Subsystem and Exchange Windows Permissions, because membership in these groups grants significant permissions including potential WriteDACL over the domain object
What should be noted about any destructive actions taken during an assessment?|They should be carefully documented, coordinated with the client to avoid disruptions, and mentioned in the final report so changes can be reverted
What is the LastLogonTimeStamp field useful for in computer enumeration?|Identifying stale machines that haven't been turned on and are missing patches; administrators may disable machines after 90 days of inactivity
Why target older Windows operating systems during an assessment?|They have fewer logging and antivirus capabilities, are more likely to be vulnerable to known exploits, and may deviate from standard builds with weaker passwords and vulnerable software
What is significant about Windows 10 Enterprise vs Professional for attackers?|Windows 10 Enterprise is the only version with Credential Guard enabled by default, which prevents Mimikatz from stealing passwords; Professional should be targeted if administrators log into both
What does the WhenCreated field reveal about a computer?|When the machine joined Active Directory; older machines are more likely to deviate from the standard build with weaker local admin passwords, more local admins, vulnerable software, and more data
What does unconstrained delegation on a computer mean?|The computer is trusted to delegate any user's credentials to any service, making it a high-value target for credential theft attacks
What does constrained delegation on a computer mean?|The computer is trusted to authenticate for other principals to specific services only, which can still be abused for delegation attacks
What does the TRUSTED_TO_AUTH_FOR_DELEGATION UAC flag indicate on a computer?|The computer is configured for constrained delegation, allowing it to authenticate on behalf of users to specific services
Why is enumerating open shares important?|Shares can hold a wealth of sensitive information including credentials, configuration files, and business data that can aid in lateral movement and privilege escalation
What does Get-DomainFileServer return?|A list of servers likely functioning as file servers in the domain
What does Get-DomainDFSShare return?|A list of all fault-tolerant distributed file systems for the current or specified domain
What does Find-DomainObjectPropertyOutlier do?|Finds user, group, or computer objects in AD that have outlier properties set, which could indicate misconfigurations or interesting targets
What does Get-DomainManagedSecurityGroup return?|All security groups in the current or target domain that have a manager set, showing group name, manager name, manager type, and whether the manager can write
What is the significance of GenericWrite privileges on a managed security group?|The group manager can modify group membership by adding or removing users, which could be leveraged for lateral movement if the manager account is compromised
