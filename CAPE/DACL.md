What are the two main variables of the Windows object security equation?|Tokens (identify security context of a process/thread) and Security Descriptors (contain security information associated with an object)
What is an ACL according to RFC4949?|A mechanism that implements access control for a system resource by enumerating the system entities permitted to access the resource and stating the access modes granted to each entity
What are the four general categories of access control policies?|Discretionary Access Control (DAC), Mandatory Access Control (MAC), Role-based Access Control (RBAC), and Attribute-based Access Control (ABAC)
How does DAC differ from MAC?|In DAC, an entity with access rights can by its own volition enable another entity to access a resource. In MAC, the entity having access cannot just by its own volition enable another entity to access that resource
What is Windows an example of in terms of access control?|A DAC operating system, which utilizes Discretionary Access Control Lists (DACLs)
What is the difference between a DACL and an ACE?|A DACL is the entire list of permission entries for an object. Individual entries within the DACL (such as Full Control or Change Password) are Access Control Entries (ACEs)
What are the six main fields a security descriptor can contain?|Revision Number, Control Flags, Owner SID, Group SID, DACL (Discretionary Access Control List), and SACL (System Access Control List)
What does the Revision Number field in a security descriptor represent?|The SRM (Security Reference Monitor) version of the security model used to create the descriptor
What do Control Flags in a security descriptor define?|Optional modifiers that define the behavior/characteristics of the security descriptor
What is the Group SID field in a security descriptor used for?|The object's primary group SID. Only the Windows POSIX subsystem utilized this member (before being discontinued), and most AD environments now ignore it
What does the DACL specify?|Who has what access to the object
What does the SACL specify?|Which operations by which users should be logged in the security audit log and the explicit integrity level of an object
What are the two forms a security descriptor can take?|Absolute (contains pointers to the information) and Self-relative (stores actual data in a contiguous memory block)
What is the purpose of self-relative security descriptors?|They are meant to store a security descriptor on a disk or transmit it over the wire
What is the Control member of a security descriptor?|A 16-bit set of bit flags (SECURITY_DESCRIPTOR_CONTROL) that qualify the meaning of a security descriptor or its components
What does the SE_DACL_PRESENT flag indicate?|A security descriptor that has a DACL. If not set or if set and the DACL is NULL, the security descriptor allows full access to everyone. An empty DACL permits access to no one
What is the difference between a NULL DACL and an empty DACL?|A NULL DACL allows full access to everyone, while an empty DACL permits access to no one
What access rights are object owners always implicitly granted?|RIGHT_WRITE_DAC (WriteDacl) and RIGHT_READ_CONTROL (ReadControl)
What are the two types of ACLs in Windows?|SACL (System Access Control List) and DACL (Discretionary Access Control List)
What are the two types of ACEs within a SACL?|System audit ACEs and system audit-object ACEs
What does an ACE contain?|A set of user rights and a SID that identifies a principal for whom the rights are allowed, denied, or audited
What are the three main members of a generic ACE structure?|ACE_HEADER (containing AceType, AceFlags, AceSize), ACCESS_MASK (Mask member defining rights), and SidStart (first 32 bits of trustee's SID)
What does ACCESS_ALLOWED_ACE do?|Allows a particular security principal (user or group) to access an Active Directory object with specified permissions such as read, write, or modify
What does ACCESS_ALLOWED_OBJECT_ACE do?|Grants access to an object and any child objects it contains, without applying separate ACEs to each child object
What does ACCESS_DENIED_ACE do?|Denies a particular security principal access to an Active Directory object with specified permissions
What does ACCESS_DENIED_OBJECT_ACE do?|Restricts access to an object and any child objects it contains, without having to apply separate ACEs to each child object
What additional members do object-specific ACEs contain compared to generic ACEs?|ObjectType (GUID for child object type, property set, extended right, or validated write), InheritedObjectType (type of child object that can inherit the ACE), and Flags (indicates whether ObjectType and InheritedObjectType are present)
Where are object-specific ACEs used?|Only within Active Directory
What is dsacls?|A native Windows binary (command-line equivalent to the Security tab in ADUC Properties) that can display and change ACEs/permissions in ACLs of AD objects
What .NET class contains the SecurityMasks property for accessing DACLs?|The DirectorySearcher class within the System.DirectoryServices namespace
What function from ActiveDirectorySecurity is used to parse a binary security descriptor?|SetSecurityDescriptorBinaryForm
What tool from Sysinternals can view specific access rights granted to users or groups?|AccessChk
What is an Access Mask?|A 32-bit value that specifies the allowed or denied rights to manipulate an object
What does GenericAll (GA) allow in AD?|Creating/deleting child objects, deleting a subtree, reading/writing properties, examining child objects and the object itself, adding/removing from directory, and reading/writing with extended rights
What is the hexadecimal value for GenericAll?|0x10000000
What does GenericExecute (GX) equate to for AD objects?|RC (ReadControl) and LC (ListContents) - reading permissions and listing contents of a container object
What does GenericWrite (GW) equate to for AD objects?|RC (ReadControl), WP (WriteProperty), and VW (ValidatedWrite) - reading permissions, writing all properties, and performing all validated writes
What does GenericRead (GR) equate to for AD objects?|RC (ReadControl), LC (ListContents), RP (ReadProperty), and LO (ListObject)
What does WriteDacl (WD) allow?|Modifying the object's security descriptor's discretionary access-control list (DACL)
What does WriteOwner (WO) allow?|Modifying the object's security descriptor's owner. A user can only take ownership but cannot transfer ownership to other users
What does ReadControl (RC) allow?|Reading data from the object's security descriptor, but not the SACL data
What does RIGHT_DS_CONTROL_ACCESS (CR) do?|Allows performing an operation controlled by a control access right. When ObjectType doesn't contain a GUID, it controls the right to perform all control access right operations (AllExtendedRights)
What does RIGHT_DS_WRITE_PROPERTY (WP) do?|Allows writing properties of the object. When ObjectType doesn't contain a GUID, it controls the right to write all object attributes
What does RIGHT_DS_WRITE_PROPERTY_EXTENDED (VW) do?|Allows performing an operation controlled by a validated write access right. Also referred to as Self
What is the GUID for User-Force-Change-Password?|00299570-246d-11d0-a768-00aa006e0529
What does User-Force-Change-Password allow?|Resetting a user's account password without knowing the old one (unlike User-Change-Password which requires the old password)
What two extended rights are required to perform a DCSync attack?|DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) and DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
What does the Self-Membership validated write allow?|Editing the member attribute, enabling setting membership of groups
What is the GUID for Self-Membership?|bf9679c0-0de6-11d0-a285-00aa003049e2
What does the Validated-SPN validated write allow?|Editing the Service Principal Name (SPN) attribute
What is the GUID for Validated-SPN?|f3a64788-5306-11d1-a9c5-0000f80367c1
What tools can enumerate DACLs on Windows?|Get-DomainObjectAcl and Add-DomainObjectAcl from PowerView, and Get-Acl/Set-Acl from built-in PowerShell Cmdlets
What tool can enumerate DACLs on UNIX-like systems?|Impacket's dacledit.py (from ShutdownRepo fork)
What are the five actions dacledit.py supports?|read, write, remove, backup, and restore
What two categories does BloodHound separate control rights into?|Inbound Control Rights (inspecting an object's DACL) and Outbound Control Rights (aggregation of all references to the object's SID in all DACLs across the domain)
What is targeted Kerberoasting?|When an attacker with the ability to edit the servicePrincipalName attribute of another user adds an SPN to make that account vulnerable to Kerberoasting
What access rights enable targeted Kerberoasting?|GenericAll, GenericWrite, WriteProperty, WriteSPN, or Validated-SPN over the target
What does targetedKerberoast.py do differently from GetUserSPNs.py?|For users without an SPN, it tries to set one, print the Kerberoastable hash, and then delete the temporary SPN
What hashcat mode is used for Kerberos 5 etype 23 TGS-REP hashes?|13100
What access rights enable the AddMembers attack on a group?|GenericAll, GenericWrite, Self, AllExtendedRights, or Self-Membership over the target group
Why can't the net tool be used to abuse Self-Membership?|Because net uses SMB protocol and remote calls to RPC protocol for group modification, which doesn't work with Self-Membership access right
What protocol should be used instead of SMB/RPC when abusing Self-Membership?|LDAP protocol
What namespace does Add-DomainGroupMember from PowerView use?|System.DirectoryServices.AccountManagement
Why must you reauthenticate after adding yourself to a group like Backup Operators?|To get a new ticket with the required group membership
What privilege does the Backup Operators group provide?|SeBackupPrivilege (and SeRestorePrivilege)
What tool exposes the Volume Shadow Copy Service (VSS) functionality for creating shadow copies?|Diskshadow.exe
Why is a shadow copy needed to get NTDS.dit?|Because the operating system actively uses the Active Directory database, preventing direct copying
What three files are needed to dump domain credentials with secretsdump.py?|SAM registry hive, SYSTEM registry hive, and ntds.dit database
What access rights enable ForceChangePassword?|GenericAll, AllExtendedRights, or User-Force-Change-Password over the target account
What is LAPS?|Microsoft's Local Administrator Password Solution - manages local admin passwords with random, cryptographically strong passwords that rotate every 30 days by default
What attribute stores the LAPS password in Active Directory?|ms-MCS-AdmPwd
What BloodHound edge identifies accounts that can read LAPS passwords?|ReadLAPSPassword
What is a limitation of dacledit.py regarding group membership?|It does not correlate groups and their members - privileges assigned to a group won't be detected when querying individual members
What are gMSAs?|Group Managed Service Accounts - provide automated password management for service accounts with passwords automatically generated, stored, and periodically rotated by AD domain controllers
Where are gMSA access rights stored?|In the msDS-GroupMSAMembership attribute of the service account
What tool can read gMSA passwords from Linux?|gMSADumper.py
What tool can read gMSA passwords from Windows?|GMSAPasswordReader
What does WriteDacl access right allow?|Modifying the DACL of a target object, enabling granting of additional rights like DCSync
What predefined rights can dacledit.py assign when modifying DACLs?|FullControl, ResetPassword, WriteMembers, and DCSync
What PowerView function modifies DACLs?|Add-DomainObjectAcl
What PowerView rights option names are available with Add-DomainObjectAcl?|All (equivalent to FullControl), ResetPassword, WriteMembers, and DCSync
What does WriteOwner access right allow?|Modifying the object's owner (OwnerSid) in the security descriptor, which then allows editing the object's DACL
What tool from Impacket can change object ownership?|owneredit.py
What is the difference between PowerView's "All" rights option and dacledit.py's "FullControl"?|They are identical - PowerView uses "All" while dacledit.py uses "FullControl"
How can you revert DACL modifications made by dacledit.py?|Use the backup file automatically generated during the write action with the -action restore option
What are Shadow Credentials?|An alternative account takeover technique that abuses Windows Hello for Business by adding Key Credentials to the msDS-KeyCredentialLink attribute and performing PKINIT Kerberos authentication
What is PKINIT?|Public Key Cryptography for Initial Authentication - allows obtaining a TGT with an x509 certificate using asymmetric pre-authentication instead of password-derived keys
What is Key Trust?|Introduced in Windows Server 2016, it enables passwordless authentication using raw key data stored in msDS-KeyCredentialLink instead of certificates
What attribute stores Key Credentials for passwordless authentication?|msDS-KeyCredentialLink
What information does a Key Credential object contain?|Creation date, distinguished name of the owner, a GUID representing a Device ID, and the public key
How does the Shadow Credential attack obtain the NTLM hash?|Through Kerberos U2U (User-to-User) authentication - requesting a service ticket to itself, then decrypting the PAC which contains the NTLM hash in NTLM_SUPPLEMENTAL_CREDENTIAL
What are the three prerequisites for Shadow Credential attacks?|At least one DC running Windows Server 2016+, Domain Functional Level of Windows Server 2016+, and the DC must have its own certificate and keys (AD CS/PKI/CA)
What error occurs if the DC doesn't have its own certificate for Shadow Credentials?|KRB-ERROR (16): KDC_ERR_PADATA_TYPE_NOSUPP
What access rights enable Shadow Credential attacks?|GenericAll, GenericWrite over the target, or WriteProperty over the target's msDS-KeyCredentialLink attribute
What tool performs Shadow Credential attacks from Windows?|Whisker
What tool performs Shadow Credential attacks from Linux?|pyWhisker (with PKINITtools for complete exploitation)
What does the Privilege Attribute Certificate (PAC) contain?|User SID, Group SIDs, User Rights, and Logon Information
What are the two methods for assigning logon scripts to users?|Using the Logon script field in the Profile tab (updates scriptPath attribute) or using a Group Policy
What file types does scriptPath support?|Batch (.bat), command (.cmd), executable (.exe), VBScript, JScript, and KiXtart - but NOT PowerShell directly
Where must Legacy logon scripts be placed?|Within the NETLOGON share (which is %systemroot%\SYSVOL\sysvol\<DOMAIN_DNS_NAME>\scripts\)
What is the relationship between NETLOGON and SYSVOL?|NETLOGON holds logon scripts that reside in the scripts folder within SYSVOL - they are the same location
What is the difference between Legacy and Modern logon scripts?|Legacy scripts are set via scriptPath attribute and must be in NETLOGON. Modern scripts are set via Group Policy and also support PowerShell
What two conditions make scriptPath abusable with write rights?|Having write permissions on the scriptPath attribute AND write permissions somewhere within the NETLOGON share
How can scriptPath be abused with only read rights?|By inspecting the file scriptPath points to for write permissions, especially when a "stub" logon script calls another script in a different share where we have write access
What is PywerView?|A partial Python port of PowerSploit's PowerView for use from Linux
What is Adalanche?|A tool similar to BloodHound CE that uses graph theory to enumerate DACLs and construct attack paths, detecting over 90 edge types
What edge does Adalanche show that BloodHound CE does not?|WriteScriptPath
What is ScriptSentry?|A tool that automates discovery of misconfigurations in logon scripts including unsafe permissions, plaintext credentials, and unsafe NETLOGON/SYSVOL permissions
What tool can modify AD attributes from Linux using LDIF format?|ldapmodify
What is bloodyAD?|An AD privilege escalation command-line utility that allows setting and getting values of objects' attributes
What is SPN Jacking?|An alternative method to abuse WriteSPN rights by mixing DACL abuse with Constrained Delegation manipulation, allowing abuse when password cracking is not possible
What is Ghost SPN-Jacking?|Targeting scenarios where an SPN previously associated with a computer/service account is no longer in use due to deletion, renaming, or removal of a custom service class
What is Live SPN-Jacking?|Active manipulation of SPNs currently in use within the network, requiring removing an SPN from one account and assigning it to the target
Why can't duplicate SPNs normally be assigned to different accounts?|Domain Controllers block duplicate SPN assignments to prevent conflicts (in environments with up-to-date security updates)
How does Live SPN-Jacking work around the duplicate SPN restriction?|First remove the SPN from the original account, then assign it to the target account
What Rubeus option substitutes an alternate service name into a ticket?|tgssub
Why is tgssub needed in SPN Jacking attacks?|Because the service ticket obtained has the wrong hostname/service class and needs to be changed to match the actual target
What is S4U2self?|A Kerberos extension that allows a service to request a service ticket to itself on behalf of another user
What is S4U2proxy?|A Kerberos extension that allows a service to use a client's service ticket to request a service ticket to another service on behalf of that client
What is the NoPAC attack?|A privilege escalation method exploiting CVE-2021-42278 and CVE-2021-42287 through sAMAccountName Spoofing to impersonate domain controllers
What does CVE-2021-42278 exploit?|The lack of restrictions on modifications to the sAMAccountName attribute - AD doesn't enforce that computer account names must end with $
What does CVE-2021-42287 exploit?|A KDC vulnerability where when a Service Ticket is requested for a non-existent account, the KDC appends a $ and searches again
What is the MachineAccountQuota (MAQ)?|A domain attribute allowing any user to join up to 10 computers to the domain by default
What attribute records the security ID of the creator of a computer object?|ms-DS-CreatorSID
What are the six steps for sAMAccountName Spoofing from Windows?|1) Create computer account, 2) Clear SPNs, 3) Change sAMAccountName to DC name without $, 4) Request TGT, 5) Revert sAMAccountName, 6) Request service ticket with S4U2self
Why must the sAMAccountName be reverted before requesting a service ticket?|So the KDC fails to find the account, appends $, and matches the legitimate DC account
What tool can scan for NoPAC vulnerability?|noPac (Windows) or noPac scanner.py (Linux)
How can you tell if a DC is vulnerable to NoPAC from the scan?|The TGT without PAC will have a different (smaller) size than the TGT with PAC, usually below 1000 bytes
What is a GPO (Group Policy Object)?|A collection of policy settings defining the appearance and behavior of systems for a specific group of users or computers
What are the two main components of a GPO?|Group Policy Container (GPC) - LDAP object with configuration/permissions, and Group Policy Template (GPT) - actual settings files within SYSVOL
Where is the GPC stored?|As an LDAP object with distinguished name containing a GUID: CN={GUID},CN=Policies,CN=System,DC=domain,DC=local
Where is the GPT stored?|In the SYSVOL directory: \\dc\SysVol\domain\Policies\{GUID}
What is the order in which GPOs are applied?|Local, Site, Domain, Organization Units (OUs) - with OU having highest priority
What happens when multiple GPOs conflict?|The GPO processed last has precedence
What does enforcing a GPO do?|Ensures its settings take precedence over any conflicting settings, even if a subordinate OU blocks inheritance
How often are Group Policies automatically refreshed?|Every 90 minutes with a random offset up to 30 minutes
What is the difference between "Edit settings" and "Edit settings, delete and modify security" GPO delegation?|"Edit settings" allows modifying GPO properties/settings. "Edit settings, delete and modify security" also allows deleting the GPO and delegating management to other users
What does Link Order determine for GPOs?|The hierarchy of GPO application when multiple GPOs are linked to the same AD container at each level
What are the four possible values for GPO link options?|0 (enabled), 1 (disabled), 2 (enforced), 3 (enforced but disabled)
What four things should an attacker enumerate regarding GPOs?|Which non-admin users can modify GPOs, where GPOs are linked, which non-admin users can link GPOs, and which non-admin users can create GPOs
What AD attribute shows where GPOs are linked?|gplink
Where are GPO objects stored in Active Directory?|CN=Policies,CN=System,DC=domain,DC=local
What right is needed to create new GPOs?|CreateChild on the Policies container (CN=Policies,CN=System)
What AD attribute type must be writable to link GPOs?|GP-Link (WriteProperty on GP-Link)
What is SharpGPOAbuse?|A .NET application that takes advantage of a user's edit rights on a GPO to compromise objects controlled by that GPO
What options does SharpGPOAbuse support?|AddUserRights, AddLocalAdmin, AddComputerScript, AddUserScript, AddComputerTask, AddUserTask
What is pyGPOAbuse?|A partial Python implementation of SharpGPOAbuse for use from Linux
What is GPOwned?|A tool for GPO enumeration from Linux
What is Get-GPOEnumeration?|A PowerView wrapper that automates GPO enumeration including rights to modify, link, and create GPOs
What warning applies when using SharpGPOAbuse --AddLocalAdmin?|It will overwrite any existing Administrators if the policy has higher priority
What Event ID logs changes to a computer account (useful for SPN Jacking detection)?|Event ID 4742
What Event ID logs Kerberos service ticket requests?|Event ID 4769
What Event ID logs Kerberos TGT requests (useful for Shadow Credential detection)?|Event ID 4768
What indicates a potential Shadow Credential attack in Event ID 4768?|Certificate Information attributes appearing non-blank when PKINIT authentication is uncommon
What Event ID logs unauthorized modifications to AD attributes like msDS-KeyCredentialLink?|Event ID 5136
What Event IDs are relevant for GPO attack detection?|5137 (Created), 5136 (Modified), 5141 (Deleted)
How do you enable GPO change auditing?|Edit Default Domain Controller Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > DS Access > Enable Audit Directory Service Changes
What mitigation prevents Shadow Credential attacks on privileged accounts?|Implement an ACE denying EVERYONE from modifying msDS-KeyCredentialLink for accounts not enrolled in Key Trust passwordless authentication
What Event ID logs sAMAccountName changes?|Event ID 4781
What is the key mitigation for sAMAccountName Spoofing?|Applying patches for CVE-2021-42278 and CVE-2021-42287 on all domain controllers
What is the Protected Users group used for in SPN Jacking mitigation?|Adding privileged accounts to prevent impersonation through Kerberos delegation
What does the msDS-AllowedToDelegateTo attribute contain?|A list of SPNs used to configure Constrained Delegation for a service
What is an orphaned SPN?|An SPN previously associated with a computer/service account that is no longer in use due to deletion or renaming of the account
What tool from Krbrelayx can manipulate SPNs from Linux?|addspn.py
What is Chisel used for in the SPN Jacking Linux attack?|Creating a SOCKS proxy to access the internal network through a compromised machine
What is the key advantage of SPN Jacking over traditional WriteSPN abuse?|Password cracking is not required
What PowerShell module provides GPO management commands like New-GPO and New-GPLink?|GroupPolicy module (part of RSAT)
What is the Rubeus createnetonly option used for?|Creating a sacrificial logon session to inject tickets into
What is the difference between Rubeus ptt and createnetonly?|ptt imports a ticket into the current session, while createnetonly creates a new process with a separate logon session for ticket injection
What tool can perform OverPass-the-Hash to launch a process with a ticket?|Mimikatz (sekurlsa::pth)
What is the significance of adminCount=1 in ACE inheritance?|Objects with adminCount=1 are excluded from inheriting ACEs when using the -inheritance flag with dacledit.py
What PowerView function is used to set properties on domain objects?|Set-DomainObject
What PowerView function changes object ownership?|Set-DomainObjectOwner
What is findDelegation.py used for?|Identifying accounts with delegation rights (unconstrained, constrained, and resource-based constrained delegation)
What is tgssub.py from ShutdownRepo?|A tool to substitute an alternate service name in a Kerberos service ticket (ccache format equivalent of Rubeus tgssub)
What is describeTicket.py used for?|Getting detailed information about a Kerberos ticket including service name, encryption type, and session key
What is PowerMad used for?|Creating and manipulating machine accounts in Active Directory (e.g., New-MachineAccount, Set-MachineAccountAttribute)
What is the Windows Hello for Business (WHfB) enrollment process?|The TPM generates a public-private key pair, the private key stays in the TPM, and the public key is stored in msDS-KeyCredentialLink (Key Trust) or used to request a certificate (Certificate Trust)
What is PKINITtools used for?|Complete exploitation of Shadow Credentials from Linux - includes gettgtpkinit.py for TGT generation and getnthash.py for NT hash extraction
How does getnthash.py extract the NT hash?|It uses the AS-REP encryption key from gettgtpkinit.py to request a U2U ticket to itself, then decrypts the PAC containing the NTLM hash
What three Whisker actions can manage msDS-KeyCredentialLink?|add (add new credential), remove (delete specific DeviceID), clear (remove all values)
What warning applies to clearing msDS-KeyCredentialLink?|Clearing the attribute on accounts configured for passwordless authentication will cause disruptions
What is the LOGONSERVER environment variable?|It evaluates to the NetBIOS name of the domain controller that authenticated the current user
What does smbcacls do?|Enables viewing ACLs on NT files or directory names via SMB
What is the significance of the -ResolveGUIDs option in PowerView?|It resolves GUIDs to their display names (e.g., showing "User-Force-Change-Password" instead of the GUID)
What are the predefined rights dacledit.py can write?|FullControl, ResetPassword, WriteMembers, and DCSync (or custom rights via -rights-guid)
What is the difference between net rpc password and rpcclient setuserinfo2 for password reset?|Both can reset passwords from Linux, but rpcclient uses the setuserinfo2 command with info level 23
What is LAPSDumper?|A Python script for reading LAPS passwords from Linux
What two PowerShell modules can dump LAPS passwords from Windows?|PowerView (Get-DomainObject with ms-mcs-AdmPwd property) and ActiveDirectory module (Get-ADComputer)
What happens when a DACL has SE_DACL_PRESENT set but the DACL is NULL?|The security descriptor allows full access to everyone
What is the hexadecimal representation of SE_SELF_RELATIVE?|0x8000
What does a Control value of 0x8014 signify?|The presence of SE_DACL_PRESENT, SE_SACL_PRESENT, and SE_SELF_RELATIVE flags
