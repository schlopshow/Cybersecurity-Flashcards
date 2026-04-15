# Red Team Operator Cheatsheet
> Structured by engagement phase. Focus on concepts, gotchas, and OPSEC decisions.

---

## 0. LEGAL & RULES OF ENGAGEMENT

- **CMA S1**: Unauthorised access. **S2**: Access with intent. **S3**: Impairing systems. **S3A**: Making/supplying tools used to commit offences. **S3ZA**: Serious damage — up to life imprisonment.
- Motive is irrelevant — good intent is not a defence (McKinnon, Cuthbert cases).
- CMA applies to UK citizens attacking foreign systems, and foreign attacks on UK systems.
- **HRA Art 8**: No access to personal/BYOD devices — breach of right to private life.
- **GDPR**: Data minimisation, storage limitation, purpose limitation. Need a Data Processing Agreement if engagement touches systems with personal data. Art 32 is the legal basis for security testing.
- Get Rules of Engagement signed before touching anything. Scope creep kills engagements and careers.

---

## 1. INITIAL ACCESS (TA0001)

### Payload Taxonomy
```
DELIVERY ( CONTAINER ( TRIGGER + PAYLOAD + DECOY ) )
```
- **Decoy** = what the victim sees after trigger fires (fake PDF, real-looking doc)
- Multi-stage chains exist to defeat automated analysis and complicate IR

### Payload Staging
| | Stager (~890 bytes) | Stageless (~307KB) |
|---|---|---|
| OPSEC | No public key validation — hijackable by fake team server | Encrypts metadata with TS public key |
| Memory | Uses RWX (bad) | RW → RX flip (good) |
| Use case | Size-constrained delivery | Preferred default |

### Payload Guardrails
Restrict stageless payload execution to: matching IP, username, hostname, or domain. Prevents detonation outside target environment.

### Loaders
- **Stomped**: Reflective DLL loading, shellcode stub overwrites DOS header — detectable
- **Prepended**: Loader prepended to PE. No header overwrite, supports encoding/encryption, doesn't need export functions — preferred

### Trigger Types
| Trigger | Notes |
|---|---|
| **LNK** | `.lnk` extension always hidden by Explorer. Custom icon. Can mimic any file type. |
| **HTA** | HTML + VBScript. Always x86 Beacon. |
| **Batch (.bat/.cmd)** | Use `@echo off`. Check `%cmdcmdline%` vs `%~f0` to detect sandbox (double-click vs CLI). |
| **MSC (GrimResource)** | XSS in MMC. mmc.exe is auto-elevating — UAC prompt if victim is local admin. |
| **XLAM** | Excel add-in. Place in `%APPDATA%\Microsoft\Excel\XLSTART` — trusted location, bypasses Protected View, Auto_Open fires. |
| **MS Office Macro** | VBA. Protected View blocks macros on MotW files — requires container bypass. |

### DLL Side-Loading
- Drop malicious DLL with correct name into writeable location in search order
- WinSxS (`C:\Windows\WinSxS`) contains old vulnerable app versions — useful candidates

### AppDomainManager Hijack (.NET)
- Inherit from `AppDomainManager`, set via env vars `APPDOMAIN_MANAGER_ASM` / `APPDOMAIN_MANAGER_TYPE` or `.config` file

### Code Signing
- **Standard cert**: Adds signature only
- **EV cert**: Makes publisher trusted by SmartScreen, removes all warnings — far more valuable
- Never sign with your own company cert. Don't submit custom artifacts to VirusTotal.

---

## 2. COBALT STRIKE — INFRASTRUCTURE & LISTENERS

### Team Server Design
- Dedicated TS per phase (initial access / post-ex / persistence)
- If one is burned, others maintain access

### Listener Types
| Type | Protocol | Notes |
|---|---|---|
| HTTP/S (Egress) | HTTP GET (fetch tasks) / POST (return results) | Default C2 channel |
| DNS (Egress) | A/AAAA/TXT lookups | Low bandwidth. Beacon appears as ghost session until tasked. |
| SMB (P2P) | Named pipe over port 445 | Waits for another Beacon to connect. Doesn't listen on TS. |
| TCP (P2P) | TCP bind | 0.0.0.0 = accept from network; 127.0.0.1 = local only |

P2P Beacons must chain back to an egress Beacon to reach the TS. Can chain multiple P2P together.

### HTTP Host Rotation Strategies
- **Round Robin**: Cycles top-to-bottom, one request per host
- **Random**: Random host per request
- **Failover**: Stays on host until N consecutive failures, then moves on
- **Rotate**: Uses each host for a fixed time period

### Redirectors
Sit between Beacon and TS. Use iptables, socat, Apache, NGINX. Never expose TS directly.

### Beacon Session Graph Line Colours
- Dashed green = HTTP/S | Solid yellow = SMB | Dashed yellow = DNS | Solid green = TCP
- Firewall icon with dashed line = egress to TS | Solid line between Beacons = P2P

---

## 3. COBALT STRIKE — PAYLOAD OPSEC

### Memory OPSEC
```
stage.userwx = false       → RW alloc → copy Beacon → flip to RX per section
stage.copy_pe_header = false → Don't copy DOS/NT headers into memory
```

### Module Stomping
Map a legitimate PE from disk, overwrite with Beacon. Memory appears backed by real on-disk module. Choose module ≥ 512KB from System32.

### String Replacement (Malleable C2)
```
stage.transform-x64 { strrep "original" "replacement"; }
```
- Replacement must be ≤ length of original
- Format specifiers must remain valid (%s, %d)
- **Never replace HTTP response strings** ("HTTP/1.1 200 OK") — breaks post-ex web server features

### Beacon Command OPSEC Tiers (Lightest → Heaviest)
1. **House-keeping** (`sleep`, `spawnto`, `ppid`) — no execution
2. **API-only** (`ls`, `ps`, `cd`, `upload`) — Win32 APIs only, no child processes
3. **BOF / Inline** — executes inside Beacon process. If it crashes, Beacon dies.
4. **Fork & Run** — spawns sacrificial process, injects reflective DLL, reads output over named pipe. Heaviest footprint.

### Fork & Run Variants
- **Spawn**: New sacrificial process (`spawnto`)
- **Explicit**: Inject into existing running process (`[arch] [pid]` arguments in command syntax)

### spawnto / ppid Spoofing
- Match host process to C2 channel (HTTP Beacon → browser process)
- ppid spoofing makes child appear as child of chosen parent
- Avoid: `msedge.exe → cmd.exe` — instantly suspicious
- `post-ex.spawnto` cannot use env vars in SYSTEM context — use explicit path via Artifact Kit `ak-settings`

### Exit Function
- `ExitThread` — injected into existing process. Don't kill it.
- `ExitProcess` — Beacon owns the process.

---

## 4. ARTIFACT & RESOURCE KIT / AMSI

### Artifact Kit
- Source templates: `main.c` (.exe), `svcmain.c` (.svc.exe), `dllmain.c` (.dll)
- `bypass-*.c` = anti-sandbox techniques
- Stack Spoof option = hides shellcode executing from unbacked memory region
- Syscall options: `none` / `embedded` / `indirect` / `indirect_randomized`

### Finding Detections
```
ThreatCheck → splits binary, scans with Defender → finds smallest malicious byte sequence
Ghidra → load artifact, find code at flagged offset → fix in source
```

### AMSI
- Vendor-agnostic scan interface. Aware: UAC, PowerShell, WSH, JS/VBS, Office VBA.
- AMSI is just the pipe — AV decides if content is malicious.
- Patching AMSI is itself often detected. Prefer cleaning the script of detectable content.
- AppLocker → PowerShell drops to **Constrained Language Mode** (ConstrainedLanguage). Blocks arbitrary .NET/Win32 API calls.
- CLM bypass: `New-Object` can still load COM objects → register HKCU COM pointing to arbitrary DLL → load via `New-Object`

---

## 5. DISCOVERY & AD ENUMERATION (TA0007)

### LDAP Basics
- Port 389 (LDAP), 636 (LDAPS), ADWS (HTTP wrapper)
- Standard domain user can query almost everything — no elevation needed

### Key LDAP Filter Syntax
```ldap
(&(condition1)(condition2))        → AND
(|(condition1)(condition2))        → OR
(!(attribute=value))               → NOT
(attribute:1.2.840.113556.1.4.803:=VALUE)  → Bitwise AND (LDAP_MATCHING_RULE_BIT_AND)
(member:1.2.840.113556.1.4.1941:=DN)       → Recursive group membership (LDAP_MATCHING_RULE_IN_CHAIN)
```

### Key Filters
```ldap
# Regular users only (not computers)
(sAMAccountType=805306368)

# Privileged/protected accounts
(adminCount=1)

# Unconstrained delegation computers
(userAccountControl:1.2.840.113556.1.4.803:=524288)

# Trust accounts
(sAMAccountType=805306370)
```

### OPSEC-Safe Enumeration Strategy
- **Avoid**: Broad `(objectClass=*)` queries — triggers Expensive Search Results Threshold
- **Avoid**: Requesting all attributes with wildcards — triggers Search Time Threshold
- **Avoid**: Narrow queries on large domains — triggers Inefficient Search Results Threshold (visits many, returns <10%)
- **Do**: Small, targeted queries spread over days/weeks. Enumerate all relevant attributes for all objects of a type in one query. Limit attribute list to essentials: `samaccounttype, distinguishedname, objectsid, ntsecuritydescriptor`

### BloodHound / BOFHound
- Default collectors are signatured — use `ldapsearch` + `BOFHound` to parse output into BloodHound-compatible JSON
- BloodHound does **not** evaluate WMI filters on GPO-to-computer edges — verify manually
- Restricted group data (local group memberships via GPO) is in `GptTmpl.inf` in SYSVOL, not LDAP — must be read separately
- SID-only nodes in BloodHound = no data collected yet. Run targeted query by `objectsid`.

### GPO / WMI Filters
- WMI filter stored in `CN=System,CN=WmiPolicy,CN=SOM` as `msWMI-Som` objects
- Filter linked to GPO via `gPCWQLFilter` attribute
- One filter per GPO max; one filter can apply to many GPOs

---

## 6. CREDENTIAL ACCESS (TA0006)

### LSASS Dumping
- Requires SYSTEM privileges
- OPSEC concern: `ObRegisterCallbacks` notifies security drivers of process handle opens
- Sysmon logs `GrantedAccess=0x1010` (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ) — minimum needed for memory read

### Mimikatz Prefixes in Cobalt Strike
```
! → Elevate to SYSTEM before running (e.g. lsadump::sam)
@ → Impersonate Beacon's thread token first (e.g. lsadump::dcsync with impersonated user)
```

### Credential Sources
| Source | Tool | Privilege Required |
|---|---|---|
| LSASS (logonpasswords) | Mimikatz | SYSTEM |
| SAM (local hashes) | `lsadump::sam` | SYSTEM |
| LSA Secrets (service accts, machine pw) | `lsadump::secrets` | SYSTEM |
| Cached domain creds | `lsadump::cache` | SYSTEM |
| DPAPI (credential manager) | Mimikatz / MS-BKRP | Medium (standard user) via DC |
| Browser saved creds | `%LOCALAPPDATA%\<vendor>\User Data\Default\Login Data` | User |
| DPAPI Backup Key | `lsadump::backupkeys` | Domain Admin |
| DCSync | `lsadump::dcsync` | Domain Admin / DA / DC account |

### Cracking Speed Reference
- NTLM: ~140 GH/s (unsalted — fast)
- AES256 Kerberos: ~1375 kH/s (salted — very slow)

### DPAPI
- Credential Manager blobs encrypted with random AES key, itself encrypted with user's DPAPI master key
- MS-BKRP: Ask DC to decrypt user's DPAPI master key — works at medium integrity
- Domain DPAPI Backup Key: decrypts **any** user's master key, domain-wide. Never auto-rotated. Treat like krbtgt.

---

## 7. USER IMPERSONATION (T1550)

### Token Concepts
- **Primary token** = assigned to process at spawn
- **Impersonation token** = thread-level, temporary identity switch
- `getuid` always shows primary token owner — impersonation doesn't change this display

### Impersonation Techniques
| Technique | What it does | Credential needed | Integrity needed |
|---|---|---|---|
| `make_token` | Creates new logon session with creds, impersonates it. Network-only impact. | Plaintext password | Medium |
| `steal_token [pid]` | Steals primary token from process of another user | None (need access to process) | High (usually) |
| `token-store` | Persists stolen token handle even after source process closes | — | — |
| Pass-the-Hash | Patches NTLM hash into logon session credential cache | NTLM hash | High |
| Pass-the-Ticket (ptt) | Injects Kerberos ticket into logon session | Ticket (kirbi) | Medium |
| Process Injection | Injects shellcode into target user's process | None (need process access) | — |

### Pass-the-Ticket Best Practice
1. `make_token DOMAIN\user fakepassword` — create isolated logon session
2. `kerberos_ptt <ticket.kirbi>` — inject into that session
3. Avoids overwriting the real user's TGT in an existing session
4. Use `kerberos_ticket_purge` to clean up. Use `rev2self` to drop impersonation.

### Using NTLM Hash for Kerberos
- Hash → RC4-encrypted tickets — weaker, more detectable. Prefer AES keys when available.

---

## 8. KERBEROS ATTACKS

### Key Concepts
- **TGT** = encrypted with krbtgt. Used to request service tickets.
- **Service ticket (TGS)** = encrypted with service account secret. Used to access a service.
- **PAC** = embedded in tickets. Contains user RID, groups, UAC flags.
- **Pre-auth** = client encrypts timestamp with password-derived key. Without it → AS-REP Roastable.

### Kerberoasting
- Request service ticket for any SPN-bearing account. Ticket encrypted with service account secret.
- Crack EncTicketPart offline.
- Target: accounts with SPNs + weak passwords.

### AS-REP Roasting
- Accounts with pre-auth disabled. AS-REP's EncASRepPart encrypted with user's secret — crack offline.

### Unconstrained Delegation
- Flag: `TRUSTED_FOR_DELEGATION` on computer `userAccountControl`
- TGTs of authenticating users cached in LSASS on that machine
- Coerce auth from DC using SpoolSample (MS-RPRN) or PetitPotam (MS-EFSRPC), capture TGT

### Constrained Delegation
- `msDS-AllowedToDelegateTo` = list of SPNs this account can delegate to
- **With Protocol Transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`): S4U2self → freely impersonate any user
- **Without Protocol Transition**: Needs existing forwardable ticket from target user
- **Service Name Substitution**: Overwrite unencrypted `sname` field in ticket to target different SPN — works if both services run under same account

### RBCD (Resource-Based Constrained Delegation)
- `msDS-AllowedToActOnBehalfOfOtherIdentity` on target computer — controlled by the back-end
- Requires: write access to that attribute + control of a principal with an SPN
- Use `msDS-MachineAccountQuota` (default 10) to create a computer account if no SPN available
- GUID for ACL enumeration: `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79`

### Ticket Forgery
| Ticket | Secret needed | Scope | Detection |
|---|---|---|---|
| **Silver Ticket** | Service/computer account hash | Single service on single machine | No TGS-REQ to KDC. 4624 without preceding 4769. Lowercase realm name. |
| **Golden Ticket** | krbtgt hash | Any service, any user, domain-wide | TGS-REQ (4769) without AS-REQ (4768). 10-year lifetime (Mimikatz default). |
| **Diamond Ticket** | krbtgt hash | Same as golden, but stealthier | Modifies real TGT — AS-REQ exists. PAC FullName may mismatch. |

Diamond Ticket OPSEC advantage: all ticket metadata (timestamps, lifetimes, flags) match domain policy because it's based on a real ticket.

Enable PAC validation to detect Silver Tickets — KDC checks krbtgt signature; Silver Tickets signed with service key fail.

---

## 9. ADCS ATTACKS

### ESC1 — Misconfigured Template (Client Auth + Enrollee Supplies Subject)
**Conditions**: ENROLLEE_SUPPLIES_SUBJECT + Manager Approval disabled + Authorized Signatures = 0 + Client Auth EKU
**Impact**: Request cert as any user, use for PKINIT → TGT → domain compromise

### ESC2 — Any Purpose / Empty EKU
Template has Any Purpose (2.5.29.37.0) or blank EKU. Can be used in place of any EKU.

### ESC3 — Certificate Request Agent EKU
Two-step: (1) Request CRA cert, (2) use CRA cert to sign a request on behalf of target user.

### ESC4 — Writable Template ACL
Dangerous ACEs: **Owner, FullControl, WriteOwner, WriteProperty, WriteDacl**
Exploit: add ENROLLEE_SUPPLIES_SUBJECT via write permissions → ESC1 path.

### ESC8 — NTLM Relay to HTTP Web Enrollment
CA has HTTP enrollment (not HTTPS with Channel Binding). Relay NTLM auth → enrol cert as target → use cert.
- Coerce DC auth → relay → get DC cert → DCSync or Kerberos auth as DC
- C2 context: must unbind port 445 on compromised host. Stop: `lanmanserver`, `srv2`, `srvnet`

### Golden Certificate (DPERSIST1)
- Extract CA's signing key pair
- Forge certs offline for any user — valid until manually revoked
- CA server = Tier 0 asset (same impact as DC compromise)

---

## 10. DOMAIN DOMINANCE

### DCSync (T1003.006)
- Requires: Domain Admin, Enterprise Admin, or DC computer account
- Mimics DRS replication protocol to pull hashes directly from DC
- Target: `krbtgt` hash (golden ticket), DPAPI backup key
- Detection: Event 4662 with GUIDs `1131f6aa...` or `89e95b76...` from non-DC IP

### Trusts
| Type | Transitivity | Direction |
|---|---|---|
| Parent/Child | Transitive | Two-way (auto) |
| Tree-Root | Transitive | Two-way (auto) |
| External | Non-transitive | One or two-way |
| Forest | Transitive | One or two-way |

- `trustDirection` 1=Inbound, 2=Outbound, 3=Bidirectional
- `trustAttributes` 4=SID filtering, 8=Forest transitive, 32=Within forest, 64=Treat as external
- **Security boundary = forest level only.** Domain admins in child domain can escalate to forest root.

### Child → Parent Escalation (SID History Abuse)
Needed: child krbtgt AES hash, child domain SID, target group SID in parent (Enterprise Admins = RID 519)
Forge golden/diamond ticket for child domain user, add parent domain privileged group SID to SID History.
SID filtering blocks this across **external forest trusts** — only works within same forest.

### Outbound Trust Abuse (Extracting Inter-Realm Key)
- DCSync the TDO object (use TDO objectGUID) → get inter-realm key (current = Out, previous = Out-1)
- Inter-realm key = password of trust account in trusted domain
- Trust account has `primaryGroupID=513` (Domain Users) — standard enum access
- Request TGT as trust account → enumerate trusted domain from outbound side

### Foreign Security Principals
- Enumerated from trusting domain's Foreign Security Principals container
- Default SIDs to ignore: S-1-5-4, S-1-5-9, S-1-5-11, S-1-5-17
- Remaining entries = explicitly granted foreign principals — find their group memberships

---

## 11. PRIVILEGE ESCALATION (TA0004)

### Account Levels
- **Medium integrity**: Standard admin user (even if in local Administrators group)
- **High integrity**: Explicitly elevated (UAC accepted)
- **SYSTEM**: LocalSystem — highest local access

### Service Attack Surface
| Technique | What's weak | MITRE |
|---|---|---|
| **Unquoted Path** | Binary path has spaces, no quotes. Windows tries C:\Program.exe, C:\Program Files\Bad.exe etc. | T1574.009 |
| **Weak File Perms** | Service binary ACL allows standard user write — overwrite with payload | T1574.010 |
| **Weak Registry Perms** | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` writable — modify ImagePath | T1574.011 |
| **DLL Search Order** | Malicious DLL placed in directory earlier in search order than legitimate DLL | T1574.001 |
| **PATH Hijack** | Writable directory added to machine PATH before System32 | T1574.007 |
| **Search Order** | Relative path in CreateProcess without lpApplicationName — follows full search order | T1574.008 |

**Service payloads must be `.svc.exe` type** — not regular `.exe`.

### UAC Bypass
- **Cobalt Strike elevators** (`runasadmin`): Run arbitrary command in high-integrity context
- **Cobalt Strike exploits** (`elevate`): Spawn new high-integrity Beacon session

### AppLocker Bypasses
| Method | Description |
|---|---|
| **Writeable dirs in default allow paths** | `C:\Windows\Tasks`, `C:\Windows\Temp`, `C:\Windows\Tracing`, `C:\Windows\System32\spool\PRINTERS` etc. |
| **LOLBAS** | Signed MS binaries in whitelisted paths that execute arbitrary code |
| **Path wildcard** | Custom rule uses overly permissive wildcard not anchored to trusted directory |
| **COM hijack via CLM** | `New-Object` → load COM → arbitrary DLL into PowerShell process |
| **DLL rules rarely enforced** | AppLocker DLL rules off by default (performance). Use `rundll32` freely. |

### SeImpersonatePrivilege → SYSTEM
Common on SQL Server, IIS service accounts. **SweetPotato**: create named pipe → coerce SYSTEM process to connect → impersonate token → spawn SYSTEM process.

---

## 12. LATERAL MOVEMENT (TA0008)

### Remote Execution Methods
| Method | Logon Type | Credentials in LSASS on target? | Notes |
|---|---|---|---|
| **WinRM** | Network | No | In-memory only. Returns output. |
| **PsExec** | Network | No | Drops svc binary to disk. Remote injection. |
| **SCShell** | Network | No | Modifies existing service, restores after |
| **SMB/CIFS** | Network | No | Requires CIFS ticket |

Network logon = no TGT on remote target = no further Kerberos auth. If you need to enumerate domain from lateral session: `make_token` or `ptt` first.

### Service Tickets for Lateral Movement
```
SMB / PsExec  →  CIFS
WinRM         →  HTTP
WMI           →  RPCSS + HOST + RestrictedKrbHost
RDP           →  TERMSRV + HOST
MSSQL         →  MSSQLSvc
```

### LOLBAS for Lateral Movement
- `MavInject.exe` — signed MS binary, injects DLLs into other processes
- Mature orgs can block LOLBAS via AppLocker/WDAC or alert on process creation events

---

## 13. MS SQL SERVER ATTACKS

### Enumeration Path
1. SPN query → find SQL servers and service accounts
2. Port scan → port 1433/TCP (SQL), 1434/UDP (SQLBrowser)
3. SQLBrowser (no role): server name, instance name, version
4. `public` role: PID, server details, query access
5. `sysadmin`: code execution

### Code Execution Methods
| Method | Returns output? | Default enabled? |
|---|---|---|
| `xp_cmdshell` | Yes | No |
| OLE Automation | No | No |
| SQL CLR | No | No |

Always **disable** any enabled procedure after use.

`xp_cmdshell` limitation: only one set of double quotes in command string. Runs as SQL service account (typically SYSTEM or service account).

### SQL Links
- Links connect SQL instances. Security context depends on config (hardcoded creds, domain creds, or current session).
- `sa` account link → sysadmin on linked server
- `RPC Out` must be enabled to call stored procedures across a link

---

## 14. PERSISTENCE (TA0003)

### User-Level (No Admin Needed)
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run       → Run on login
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce  → Run once on login, then deleted
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup → Startup folder
HKCU\Environment → UserInitMprLogonScript = <path>      → Logon script (T1037.001)
$HOME\Documents\WindowsPowerShell\Profile.ps1           → PS profile (T1546.013) — must not block!
```
For PowerShell profile: use `Start-Job` if payload blocks execution.

### Elevated Persistence
| Technique | Notes |
|---|---|
| **Scheduled Task** (T1053.005) | SYSTEM context. Triggers: time, idle, boot, logon, event. Defined as XML. |
| **WMI Subscription** | Stored in WMI repository. Survives reboot. Runs as SYSTEM. |

### WMI Persistent Subscription — Three Required Components
1. **`__EventFilter`** — WQL query defining trigger (e.g. Win32_NTLogEvent, system startup)
2. **`__EventConsumer`** — Action to take (`ActiveScriptEventConsumer` or `CommandLineEventConsumer`)
3. **`__FilterToConsumerBinding`** — Links filter to consumer

All stored in `root/subscription` namespace.

**Remote trigger trick**: Watch for Event ID 5152 (firewall packet drop) on specific port → attacker sends packet from outside to trigger payload. Requires Audit Filtering Platform Packet Drop policy enabled.

### COM Hijacking (T1546.015)
Two opportunities:
1. CLSID exists in HKLM but not HKCU → write HKCU entry (standard user)
2. COM entry points to non-existent DLL in writable location

Find with ProcMon: filter `Operation=RegOpenKey`, `Path contains InprocServer32`, `Result=NAME NOT FOUND`.
Test on own VM first. Set `ThreadingModel` appropriately ("Both" or "Apartment").

---

## 15. PIVOTING (T1090)

### SOCKS Proxy
- Beacon's sleep time directly impacts tunnelling speed — lower sleep for interactive pivoting
- Detection surface via SOCKS: network traffic only (no BOF/DLL execution indicators on host)
- Use **Proxifier** (Windows) to route specific IP ranges through proxy — not all traffic

### Kerberos Through Proxy
- Must use hostnames (not IPs) — add static host entries on attacking machine
- WSL inherits Windows host entries automatically
- Request service tickets manually — Windows can't do it automatically in this context
- Ticket formats: Windows/Rubeus = kirbi | Linux/Impacket = ccache
- Convert: `ticketConverter.py` (Impacket)
- Set `KRB5CCNAME=/path/to/ticket.ccache` for Linux tools
- Use `proxychains` with flags: `-n` (no DNS) `-sT` (TCP connect) `-Pn` (skip ping) — ICMP/UDP don't work through SOCKS

---

## 16. REPORTING

### Cobalt Strike Report Types
- **Activity** — overall timeline
- **Hosts** — per-host data (services, creds, sessions)
- **IOC** — C2 profile, domains, file hashes (threat intel style)
- **Sessions** — activity by session
- **Social Engineering** — phishing results
- **TTP** — MITRE ATT&CK mapping

Reports aggregate across all connected team servers automatically. Use as appendices, not final deliverable.

### Final Report Structure
1. **Executive Summary** — non-technical. Business risk. For C-suite.
2. **Goals & Scenario** — methodology, scope, testing model, RoE summary.
3. **Attack Narrative** — technical sequence. Commands, output, screenshots. For technical readers.
4. **Observations & Recommendations** — deficiency per finding (prevent/detect/respond). One or more recommendations each.
5. **Conclusion** — key findings, significance, overall business risk statement.

### Out-Briefs
- **Executive brief** (management): Focus on business impact. Essential for buy-in on staffing/funding recommendations.
- **Technical brief** (blue team): Detailed review of activity. Learning opportunity for both sides. Best chance for offensive/defensive collaboration.

---

## QUICK REFERENCE — OPSEC DECISIONS

| Situation | Do This |
|---|---|
| Running post-ex commands on a sensitive target | BOF > Fork&Run Explicit > Fork&Run Spawn |
| Beacon in browser process doing HTTP C2 | Don't spawn cmd.exe as child — use ppid spoof |
| Need to dump LSASS | Expect 0x1010 GrantedAccess in Sysmon. Consider alternative sources (SAM, LSA secrets, DPAPI). |
| Injecting TGT for another user | `make_token` with fake password first → inject into that new session |
| LDAP enumeration against mature defender | Small targeted queries, spread over time. Specify only needed attributes. |
| Moving laterally via WinRM/PsExec | No TGT on target. Use `make_token` or `ptt` before domain enumeration. |
| SQL code execution needed | `xp_cmdshell` if output needed, OLE/CLR otherwise. Disable after use. |
| Persistence via COM | Test on your own VM first. Don't pick COM loaded every 5 seconds. |
| AppLocker environment | Check writeable dirs in `%WINDIR%`, look for LOLBAS, try CLM COM bypass, DLL rules likely off |
