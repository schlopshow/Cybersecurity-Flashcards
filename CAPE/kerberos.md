What is constrained delegation?|A delegation type introduced with Windows Server 2003 that restricts the services a server can impersonate a user for, allowing administrators to specify application trust boundaries
Why can an attacker modify the service name in a TGS ticket without invalidating the request?|Because the service name (SPN) is in the unencrypted part of the TGS ticket, while the user's information and session key are in the encrypted part
What is the limitation of modifying the SPN in a constrained delegation attack?|The attacker can only access different services exposed by the same account, not services on different accounts, since the TGS ticket content is encrypted with the target service account's key
Why are machine accounts particularly vulnerable to SPN modification in constrained delegation?|Machine accounts expose multiple services (CIFS, SPOOLER, TERMSRV, etc.), so modifying the SPN allows access to all services offered by that account
What does the TRUSTED_TO_AUTH_FOR_DELEGATION UAC attribute indicate?|The account has constrained delegation with protocol transition set, meaning it can use S4U2Self to impersonate any user without waiting for their authentication
What is protocol transition in constrained delegation?|It allows a service to use S4U2Self to pretend to be any user arbitrarily, even if the user authenticated via a non-Kerberos protocol like NTLM
What three steps does Rubeus perform in a constrained delegation attack?|1) Requests a TGT as the compromised service account, 2) Performs S4U2Self to get a TGS as the target user, 3) Uses S4U2Proxy to get a TGS for the target service with the alternate SPN
What are the three types of delegation in Active Directory?|Unconstrained, Constrained, and Constrained with Protocol Transition
How does Impacket's psexec.py handle SPN modification automatically?|It looks for any suitable cached TGS ticket and changes the sname from the cached SPN to the needed SPN (e.g., TERMSRV to CIFS) on the fly
What is Resource-Based Constrained Delegation (RBCD)?|A delegation type introduced with Windows Server 2012 where delegation settings are configured on the target service rather than the source service account, using security descriptors instead of an SPN allowed list
What attribute stores the RBCD trust list?|msDS-AllowedToActOnBehalfOfOtherIdentity
What two elements are required to carry out an RBCD attack?|1) Access to a user/group with privileges to modify msDS-AllowedToActOnBehalfOfOtherIdentity on a computer (GenericWrite, GenericAll, WriteProperty, or WriteDACL), 2) Control of another object that has an SPN
What is ms-DS-MachineAccountQuota?|A domain attribute that allows authenticated users to join up to 10 computers to the domain by default, enabling creation of fake computer accounts for RBCD attacks
What tool can create a fake computer account for RBCD attacks using PowerShell?|PowerMad (New-MachineAccount)
What tool can create a fake computer account for RBCD attacks from Linux?|Impacket's addcomputer.py
What Python script can configure RBCD from Linux?|rbcd.py
How do you perform RBCD when MachineAccountQuota is set to 0?|Use a method discovered by James Forshaw: obtain a TGT, get the session key, change the user's password to match the session key using SamrChangePasswordUser, then use S4U2self+U2U with the -u2u flag
What is the Golden Ticket attack?|Forging and signing TGTs using the krbtgt account's password hash, allowing impersonation of any user with arbitrary group memberships
Why is the krbtgt account password change process complex?|The password must be changed twice with full AD forest convergence between changes (typically 24 hours), because the current and previous passwords are both stored and DCs use this key to authenticate with each other
What four pieces of information are needed to forge a Golden Ticket?|Domain Name, Domain SID, Username to impersonate, and KRBTGT's NTLM hash
What is the PAC (Privilege Attribute Certificate)?|A data structure within Kerberos tickets containing user information such as name, group memberships, and other security data, copied into each TGS ticket so services know who they are dealing with
Why can an attacker with the krbtgt hash forge arbitrary tickets?|Because the krbtgt key encrypts TGTs, so knowing it allows decrypting any TGT, modifying the PAC (e.g., adding Domain Admins membership), and re-encrypting it
What is a key persistence benefit of Golden Tickets?|Resetting the impersonated account's password does not invalidate the ticket, and the ticket can have a lifespan of up to 10 years (Mimikatz default)
How can Golden Tickets be detected?|The account DOMAIN field is blank, or contains the FQDN instead of the short domain name; also unusually long ticket lifespans can be flagged as IoCs
What must be done to remove Golden Ticket persistence?|The krbtgt account password must be changed twice, with full domain convergence between changes
What Impacket tool can retrieve the domain SID?|lookupsid.py
What Impacket tool can forge Golden and Silver Tickets from Linux?|ticketer.py
How do you use a forged ticket from Linux with Impacket tools?|Export the ccache file path to the KRB5CCNAME environment variable and use any Impacket tool with the -k parameter
What is a Silver Ticket?|A forged TGS (Service Ticket) created using a service or machine account's NTLM hash, granting access to that specific service
How does a Silver Ticket differ from a Golden Ticket in scope?|A Silver Ticket can only access the specific service it was forged for on a single machine, while a Golden Ticket grants access to any service in the domain
Why are Silver Tickets more stealthy than Golden Tickets?|Silver Tickets do not require communication with the Domain Controller, and associated event logs are only created on the target host
What information is needed to forge a Silver Ticket?|Domain SID, NTLM hash of the service/machine account, target host, service name (SPN), arbitrary username, and group information
Why is Mimikatz's output misleading when creating Silver Tickets?|Mimikatz calls it a "Golden ticket" in the output, but if a /service and /target are specified, it actually generates a TGS (Silver Ticket)
Why can Silver Tickets provide long-term persistence?|Computer account password rotation may be disabled, and AD does not prevent computer accounts from accessing resources
How can Silver Tickets be detected?|The account DOMAIN field is blank, or contains DOMAIN FQDN instead of just the domain name
What is a Pass-the-Ticket (PtT) attack?|A lateral movement method that takes a user's TGT or TGS ticket and uses it to authenticate to services without touching LSASS or knowing the password
What is a Sacrificial Process and why is it critical?|A new Logon Session created specifically for injecting Kerberos tickets, preventing overwriting of existing tickets that could cause service outages (e.g., the machine account losing its ticket)
Why is creating a Sacrificial Process important for Kerberos attacks?|Overwriting an existing Logon Session's Kerberos ticket can take down services; if SYSTEM$ loses its ticket, it may not get another until reboot
What Rubeus action creates a Sacrificial Process?|createnetonly (creates a new process with LOGON_TYPE = 9 / NetOnly)
Why does Rubeus createnetonly require administrative rights?|To interact with the NetOnly process it spawns to create the Logon Session; C2 frameworks like Cobalt Strike can do this without admin rights using named pipes
How can you create a Sacrificial Process without admin rights in a C2 framework?|Use the maketoken feature (available in Covenant or Cobalt Strike) instead of Rubeus's NetOnly option
What Rubeus action lists all readable tickets?|triage
How can you extract a specific ticket using Rubeus?|Use Rubeus dump with /luid: to specify the logon session and /service: to specify the service ticket type
How can a stolen TGT be renewed using Rubeus?|Use Rubeus renew with the /ticket: parameter containing the base64-encoded ticket, and /ptt to inject the new ticket into memory
What is Kerbrute used for?|Username enumeration and password spraying against Active Directory using the Kerberos protocol
Why is Kerberos-based password spraying potentially stealthier than other methods?|Pre-authentication failures do not trigger the traditional "An account failed to log on" event 4625; only one UDP frame is sent to the KDC per attempt
How does Kerbrute enumerate usernames?|It sends TGT requests with no pre-authentication; if KDC responds with PRINCIPAL UNKNOWN, the username doesn't exist; if it prompts for pre-authentication, the username exists
What Windows event ID does Kerbrute username enumeration generate?|Event ID 4768 (if Kerberos logging is enabled)
What two event IDs does Kerbrute password spraying generate?|Event ID 4768 (TGT requested) and Event ID 4771 (Kerberos pre-authentication failed)
What is the primary mitigation for AS-REP Roasting?|Don't set users with Kerberos pre-authentication disabled; enable pre-authentication for all accounts where possible
What are key mitigations for Kerberoasting?|Use long complex passwords for service accounts, utilize Group Managed Service Accounts (GMSA), limit service account privileges, and rotate KRBTGT password at least every 180 days
How often should the KRBTGT password be rotated?|At least every 180 days
What are key mitigations for delegation abuse?|Disable unconstrained delegation where possible, place users/service accounts in Protected Users group, use "Account is sensitive and cannot be delegated" setting, and follow least privilege principle
What does the Protected Users group prevent regarding delegation?|It blocks its members from being used for Kerberos delegation and keeps their TGTs off hosts after authentication
What does the "Account is sensitive and cannot be delegated" setting do?|Prevents the account's TGS tickets from being marked as forwardable, blocking delegation of that user's authentication
What are key mitigations for Golden Ticket attacks?|Implement least privilege access, limit admin accounts, don't expose services like RDP externally, use MFA, and deploy endpoint detection tools
What are key mitigations for Silver Ticket attacks?|Ensure service accounts have 25+ character passwords, use Managed Service Accounts with regular rotation, don't place service accounts in privileged groups, limit service account permissions
What are key mitigations for Pass-the-Ticket?|Monitor process creation/destruction events, check for unusual TGT/TGS requests, implement privileged identity management, monitor named and anonymous pipes
What encryption type should be preferred over RC4 for Kerberos?|AES (Advanced Encryption Standard) - either AES-128 or AES-256
Why is disabling RC4 encryption not always recommended?|It can break legacy software and services, making it difficult to find the root cause; instead, set AES as preferred and monitor RC4 usage as rare/suspicious events
What is the value of a honeypot account for Kerberoasting detection?|A strong-password honeypot account with an SPN set can alert when someone requests its TGS ticket with weak RC4 cipher, indicating an attacker is in the environment
What PowerShell event IDs should be monitored?|Log events: 400, 800 (PowerShell log); 4100, 4103, 4104 (PowerShell Operational log)
What is AMSI?|Anti-Malware Scan Interface - available in Windows 10/11, enables all script code to be scanned before execution by PowerShell and other Windows scripting engines
What are indicators of suspicious PowerShell activity?|Remote PowerShell attempts, .Net framework downloads, Invoke-Expression/iex usage, encoded commands, Invoke-Mimikatz calls, execution policy changes, System.Reflection strings, hidden windows
What useful Windows event codes should be monitored for Kerberos attacks?|4624 (Successful Logon), 4634 (Successful Logoff), 4672 (Special Privileges Assigned), 4768 (TGT Requested), 4769 (TGS Requested), 4770 (TGS Renewed)
What anomalies in event 4624 can indicate Golden/Silver Ticket usage?|Account Domain field is blank, contains FQDN instead of short name, or contains unusual values; Account Name doesn't match Security ID
What sample query can detect Kerberoasting?|Event ID 4769, Service Name not krbtgt or ending in $, Failure Code 0x0, Ticket Encryption Type 0x17 (RC4-hmac), Ticket Options 0x40810000
What is Kerberos?|A stateless authentication protocol based on tickets that decouples user credentials from resource requests, using symmetric-key authentication with optional asymmetric features like PKINIT
What port does Kerberos use by default?|Port 88
What has Kerberos been the default authentication protocol for since Windows 2000?|Domain account authentication
What is the KDC (Key Distribution Center)?|The centralized authentication server that knows all accounts' credentials and issues tickets; in Active Directory, this is the Domain Controller
What is a TGT (Ticket Granting Ticket)?|The user's "identity card" containing all user information (name, groups, etc.), encrypted with the KDC's key, limited to a few hours by default
What is a TGS ticket (Ticket Granting Service ticket)?|A service-specific ticket containing a copy of the user's information from the TGT, encrypted with the target service account's key; also called a Service Ticket (ST)
How is the TGT protected from user tampering?|It is encrypted with the KDC's secret key, which only the KDC knows, so the user cannot read or modify their information
How is the TGS ticket protected from user tampering?|It is encrypted with the service's secret key, which the user does not know, preventing modification of access rights
What advantage does Kerberos have over NTLM authentication?|With NTLM, the password hash is stored in memory and can be stolen for Pass-the-Hash attacks on any resource; with Kerberos, tickets are service-specific and time-limited
What is the Double Hop Problem in Kerberos?|When accessing machines remotely via WinRM with Kerberos, credentials must be specific for every machine; you cannot use one connection to access other machines as that user without re-authentication
What are the three phases of Kerberos authentication?|Authentication Service (AS) for TGT request, Ticket-Granting Service (TGS) for service ticket request, and Application Request (AP) for service access
What is an AS-REQ?|The initial request from a user to the KDC for a TGT, containing an authenticator (current timestamp encrypted with user's key) and the username in cleartext
What is Kerberos pre-authentication?|The step where the user proves identity by encrypting the current timestamp with their key; if the KDC can decrypt it, the user is authenticated
What happens if pre-authentication is disabled for an account?|The client doesn't need to send an authenticator; the KDC will send the TGT regardless, making the account vulnerable to AS-REP Roasting
What is contained in an AS-REP?|The TGT (encrypted with KDC's key, containing user info and a copy of the session key) and the session key (encrypted with the user's key)
Why is the session key duplicated in the AS-REP?|One copy is in the TGT (protected with KDC's key for future KDC use) and one is separately encrypted with the user's key (so the user can extract it)
What three things does a TGS-REQ contain?|The name of the service to access (SPN), the TGT received previously, and an authenticator encrypted with the user/KDC session key
How does the KDC validate a TGS-REQ if Kerberos is stateless?|It decrypts the TGT (which it can do because it's encrypted with its own key) to extract the session key, then uses that session key to verify the authenticator
What does a TGS-REP contain?|A service ticket containing the SPN, user information, and a user/service session key - all encrypted with the service's key, plus the session key encrypted with the user/KDC session key
What does an AP-REQ contain?|The TGS ticket (encrypted with service's key) and an authenticator encrypted with the user/service session key
How does the service validate an AP-REQ?|It decrypts the TGS ticket with its own key, extracts the user/service session key, uses that to verify the authenticator, then reads the user's PAC to determine access rights
What does the service send back in an AP-REP?|The timestamp encrypted with the extracted session key, allowing the client to verify the service's identity
What are the two main categories of Kerberos ticket request attacks?|AS-REP Roasting (attacking the AS-REQ/AS-REP exchange when pre-auth is disabled) and Kerberoasting (attacking the TGS-REQ/TGS-REP exchange to crack service account passwords)
What are the three types of Kerberos delegation attacks?|Unconstrained delegation, constrained delegation, and resource-based constrained delegation
What are the two types of ticket forging attacks?|Golden Ticket (forging TGTs using krbtgt key) and Silver Ticket (forging TGS tickets using service account key)
What is AS-REP Roasting?|An attack targeting accounts with pre-authentication disabled, where the attacker obtains an encrypted TGT (AS-REP) and performs offline password cracking against the session key portion encrypted with the user's password
What Hashcat hash-mode is used for AS-REP Roasting?|18200 (Kerberos 5, etype 23, AS-REP)
What UAC flag makes an account vulnerable to AS-REP Roasting?|DONT_REQ_PREAUTH
How can AS-REP Roasting be performed as a targeted attack?|If you have GenericWrite or GenericAll over an account, you can enable the DONT_REQ_PREAUTH flag, obtain the AS-REP hash, crack it, then disable the flag again
What is the XOR value to toggle DONT_REQ_PREAUTH using PowerView?|4194304
Can AS-REP Roasting be performed without any domain credentials?|Yes, the only information needed is the username; no prior authentication is required
How can GetNPUsers.py find AS-REP Roastable accounts without credentials?|Use the -usersfile flag with a list of usernames and -no-pass flag; it will try each account and return hashes for vulnerable ones
How can Red Teams use AS-REP Roasting for persistence?|Setting the DONT_REQ_PREAUTH flag on accounts allows regaining access after password changes, especially useful on accounts outside typical monitoring scope
How can AS-REP Roasting be used for privilege escalation?|When you have GenericWrite/GenericAll but can't log in without knowing the password, enable the flag and try to crack the hash instead of resetting the password (which would raise alarms)
What is Kerberoasting?|An attack against service accounts where the attacker requests TGS tickets for accounts with SPNs, then performs offline password cracking against the tickets encrypted with the service account's password
What is required to perform a Kerberoasting attack?|A valid domain user account and password (even lowest privileged), or SYSTEM/low-privileged shell on a domain-joined host
Why are machine accounts ($) not practical targets for Kerberoasting?|Machine accounts have 120-character randomly generated passwords, making brute forcing impractical
What makes user accounts with SPNs vulnerable to Kerberoasting?|User accounts have human-set passwords that are more likely to be predictable and crackable
What is an SPN (Service Principal Name)?|An LDAP attribute set on an account indicating the list of services provided by that account; it's an alias to the actual AD Account containing machine name, port, and password hash
What LDAP filter finds Kerberoastable user accounts?|(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))
What Hashcat hash-mode is used for Kerberoasting?|13100 (Kerberos 5, etype 23, TGS-REP)
What does the /tgtdeleg flag in Rubeus do for Kerberoasting?|Forces RC4 encryption for tickets even when AES is configured, making them easier to crack; works in domains where RC4 is available as a backward-compatibility failsafe
How can you distinguish RC4 vs AES encrypted Kerberoast hashes?|RC4 hashes start with $krb5tgs$23$* prefix; AES hashes start with $krb5tgs$18$* prefix
What Rubeus flags help with targeted Kerberoasting?|/pwdsetafter and /pwdsetbefore to target accounts with passwords set within specific date ranges; /stats to list statistics without sending requests
Can Kerberoasting be performed without a valid domain password?|Yes, if you know an account with DONT_REQ_PREAUTH set, you can use Rubeus with /nopreauth to request TGS tickets using an AS-REQ
What is unconstrained delegation?|A delegation type where the user's TGT is embedded in the TGS ticket sent to the service, allowing the service to impersonate the user to access ANY other service
What UAC flag indicates unconstrained delegation?|TRUSTED_FOR_DELEGATION
What privilege is needed to set unconstrained delegation on an account?|SeEnableDelegationPrivilege - only administrators or explicitly privileged users can set this; a service account cannot modify itself
Where is a user's TGT stored during unconstrained delegation?|The TGT is embedded in the TGS ticket and cached in memory on the server with unconstrained delegation enabled
What is the Printer Bug (MS-RPRN)?|A flaw in the Print System Remote Protocol where any domain user can force a server to authenticate to any arbitrary host over SMB using the RpcRemoteFindFirstPrinterChangeNotificationEx method
How can the Printer Bug be combined with unconstrained delegation?|Force a Domain Controller to authenticate to a host with unconstrained delegation, capture the DC's TGT from the embedded TGS ticket, then use it for DCSync or other attacks
What tool is used to exploit the Printer Bug?|SpoolSample (or printerbug.py/dementor.py from Linux)
What Rubeus action monitors for incoming TGTs on a compromised host?|monitor (with /interval: to set check frequency and /nowrap for single-line base64 output)
How can you use a captured TGT to request a new TGS ticket?|Use Rubeus asktgs with the /ticket: parameter containing the captured TGT and /service: for the target SPN, with /ptt to inject into memory
What is the S4U2self technique for non-Domain Controller targets?|Use Rubeus s4u /self with /impersonateuser and /altservice to forge a service ticket for any service on behalf of any user, using a captured computer account ticket
What is constrained delegation's msDS-AllowedToDelegateTo attribute?|An attribute on the service account storing the list of SPNs to which the account is allowed to delegate authentication
What two modifications are made in a constrained delegation TGS request compared to a normal one?|The additional tickets field contains a copy of the user's TGS ticket, and the cname-in-addl-tkt flag tells the DC to use the user's info from the additional ticket instead of the server's
What does S4U2Proxy do?|Allows a service to obtain a valid TGS ticket for another service on behalf of a user, by embedding the user's TGS ticket in the request
What does S4U2Self do?|Allows a service to obtain a forwardable TGS ticket to itself on behalf of an arbitrary user, used when the user authenticated via non-Kerberos protocol (e.g., NTLM)
What is the relationship between S4U2Self and protocol transition?|S4U2Self enables protocol transition - if "Use any authentication protocol" is selected for constrained delegation, the service can use S4U2Self to create TGS tickets for arbitrary users
What happens when "Use Kerberos only" is selected for constrained delegation?|The service account cannot do protocol transition and cannot use S4U2Self, so it must wait for users to authenticate via Kerberos
How does RBCD differ from regular constrained delegation in terms of who controls the trust?|In RBCD, the target resource controls its own trusted list (which accounts can delegate to it), rather than the source service specifying which services it can delegate to
Can a service account modify its own RBCD trusted list?|Yes, unlike unconstrained and constrained delegation, a service account has the right to modify its own msDS-AllowedToActOnBehalfOfOtherIdentity attribute
What minimum DC version is required for RBCD?|At least one Domain Controller running Windows Server 2012 or later in the same domain
How can unconstrained delegation on user accounts be exploited from Linux?|Create a fake DNS record pointing to your attack machine, add a CIFS SPN for that DNS entry to the compromised user account, use the Printer Bug to coerce DC authentication, capture the TGT with krbrelayx.py
What tool suite is used for the unconstrained delegation user attack from Linux?|Dirkjanm's krbrelayx tools (dnstool.py, addspn.py, printerbug.py/dementor.py, krbrelayx.py)
Why do you need to create a DNS record for the unconstrained delegation user attack?|To create a fake computer identity that the DC will attempt to authenticate to via SMB, shipping a copy of its TGT in the TGS ticket to your controlled IP address
What does krbrelayx.py need to decrypt the received TGS ticket?|The compromised account's NT hash (secret key), since the TGS ticket is encrypted with the service account's password
What attack can be performed with a captured Domain Controller TGT?|DCSync attack using secretsdump.py to dump all domain credentials
How should sensitive accounts be protected against unconstrained delegation abuse?|Mark them as "Account is sensitive and cannot be delegated" or place them in the Protected Users group
What does the Protected Users group do regarding TGTs?|Blocks members from being used for Kerberos delegation and keeps their TGTs off hosts after authentication
What is the SDDL used for in RBCD attacks?|Security Descriptor Definition Language - used to create the security descriptor that gets written to msDS-AllowedToActOnBehalfOfOtherIdentity
What additional services can be requested with Rubeus /altservice in RBCD?|host, RPCSS, wsman, http, ldap, krbtgt, cifs - multiple services can be specified comma-separated
How do you clean up after an RBCD attack?|Clear the msDS-AllowedToActOnBehalfOfOtherIdentity attribute using Set-DomainObject -Clear
What Windows built-in binary can search for SPN accounts?|Setspn
What PowerView function enumerates SPN accounts?|Get-DomainUser -SPN
What PowerView function directly performs Kerberoasting?|Invoke-Kerberoast (or Get-DomainUser * -SPN piped to Get-DomainSPNTicket)
What Rubeus /stats flag does for Kerberoasting?|Lists statistics about Kerberoastable accounts without actually sending any ticket requests
What is the significance of the /nowrap flag in Rubeus?|Outputs base64-encoded tickets on a single line for easier copy-paste
What is the difference between /ptt and /ticket in Rubeus?|/ptt passes the ticket directly into memory for the current session; /ticket saves the ticket to a file for later use
What tool from Impacket finds delegation privileges?|findDelegation.py
What tool from Impacket requests service tickets for constrained delegation attacks?|getST.py
What is pypykatz used for in the RBCD MAQ=0 attack?|Converting a plaintext password to its NT hash for use in the attack chain
What is changepasswd.py used for in the RBCD MAQ=0 attack?|Changing the user's password hash to match the TGT session key using SamrChangePasswordUser method
What is describeTicket.py used for?|Examining ticket details including the Ticket Session Key needed for the RBCD MAQ=0 attack
What flag in getST.py enables the U2U technique for RBCD without machine accounts?|The -u2u flag
