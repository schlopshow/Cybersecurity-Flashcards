What are AnyDesk and TeamViewer used for in corporate environments?|Providing IT support, enabling remote work, managing systems remotely, screen sharing, file transfer, and remote printing
What MITRE ATT&CK technique covers the use of remote access software like AnyDesk and TeamViewer for command and control?|T1219
Which threat group used AnyDesk for remote access and persistence?|Cobalt Group
Which threat group abused TeamViewer for remote interactive command and control?|Carbanak group
What protocol does VNC use to transmit keyboard, mouse events, and graphical screen updates?|Remote Frame Buffer (RFB) protocol
What is the default port VNC runs on?|Port 5900
What MITRE ATT&CK technique covers VNC for lateral movement?|T1021.005
What limitation exists when using VNC for remote access?|Only the console session can be captured
Where does TightVNC store its password in the Windows registry?|HKLM\SOFTWARE\TightVNC\Server under the Password key
How is the TightVNC registry password encrypted?|Using DES-CBC encryption with a known fixed key (e84ad660c4721ae0)
What is the PasswordDecrypts repository used for?|Searching for registry keys that common VNC software uses to store passwords
Why do administrators often use shared VNC passwords across multiple computers?|To facilitate VNC administration across the environment
What is MeshCentral?|A powerful open-source remote management tool that allows administrators to manage and monitor devices remotely
What port does MeshCentral use by default for agent connections?|Port 443
How does MeshCentral's agent-based installation method work?|It creates a service on the remote computer that connects to the MeshCentral server via port 443
Why can MeshCentral agents still connect even if most ports are blocked?|Because port 443 is commonly left open for HTTPS traffic, remote management, or software deployment
What capabilities does MeshCentral provide for remote administration?|Remote desktop control, file transfer, terminal access, and monitoring of devices
What are some common software deployment and remote management tools?|Microsoft Intune, SCCM, PDQ Deploy, MeshCentral, ManageEngine Desktop Central, SolarWinds Orion, Kaseya VSA, Ivanti Endpoint Manager
What is WSUS?|Windows Server Update Services - a Microsoft service that allows administrators to distribute updates and patches for Microsoft products throughout an environment
What rights are required to access the WSUS service?|Administrative privileges on the WSUS server - membership in either the Administrator Group or the WSUS Administrator Group
What registry key reveals if WSUS is configured on a server?|HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate (WUServer value)
What is SharpWSUS?|A CSharp tool for lateral movement through WSUS
What restriction does WSUS have on executing binaries?|WSUS can only execute Microsoft-signed binaries
Why is PSExec used as the payload in WSUS attacks?|Because it is a signed Microsoft binary that allows command execution, meeting WSUS's requirement for Microsoft-signed binaries
What are the three main SharpWSUS commands used in the WSUS attack process?|Create (make malicious patch), Approve (deploy to targets), Delete (clean up)
What event ID does the WSUS Service generate if content file download fails?|Event ID 364
What is WSUSpendu?|A PowerShell tool that allows injection of malicious updates into WSUS, forcing systems to execute arbitrary commands
What is Thunder_Woosus?|A C# tool designed for manipulating WSUS updates and enabling arbitrary command execution on targeted machines
Why are WSUS services compelling targets in Windows environments?|Even within restricted or highly secured networks, they can be exploited to compromise any machine that trusts the WSUS server
What are the key considerations when searching for lateral movement opportunities?|Available assets such as users, passwords, networks, computers, services, and how services interact within the network
Are administrative rights always necessary for lateral movement?|No - services such as PSRemoting, RDP, WMI, DCOM, and SSH allow non-administrators to execute commands
Why is IPv6 relevant to lateral movement?|IPv6 is enabled by default on Windows, and firewalls may block IPv4 connections but overlook IPv6, allowing bypass of restrictions
What is RDP?|Remote Desktop Protocol - a proprietary Microsoft protocol providing a graphical interface to connect to another computer over a network
What is the default port for RDP?|TCP port 3389
Who can connect via RDP by default?|Only members of the Administrators or Remote Desktop Users groups
What does the (Pwn3d!) indicator mean for RDP in NetExec?|It means the user has rights to connect to RDP, not necessarily that they have administrative rights
What is Restricted Admin Mode for RDP?|A security feature that performs a network logon instead of an interactive logon, preventing credential caching on the remote system
What registry key controls Restricted Admin Mode?|HKLM\SYSTEM\CurrentControlSet\Control\Lsa with the DisableRestrictedAdmin value
What value enables Restricted Admin Mode?|DisableRestrictedAdmin set to 0
What attacks does Restricted Admin Mode enable when it's turned on?|Pass the Hash and Pass the Ticket attacks via RDP
Who can abuse Restricted Admin Mode?|Only members of the Administrators group
What is SharpRDP?|A .NET tool that allows non-graphical, authenticated remote command execution through RDP using the mstscax.dll library
What is the character limit for SharpRDP command execution?|259 characters
Where does SharpRDP leave traces of command execution?|In the RunMRU registry key (HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE under Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU)
What tool can clean SharpRDP command traces?|CleanRunMRU
What advantages does RDP provide for lateral movement?|Evading detection (common traffic), non-admin access possible, and persistent access
What is SMB?|Server Message Block - a network protocol for sharing files, printers, and resources among computers, supporting interprocess communication
What ports does SMB use?|TCP 445 and TCP 139 (optionally TCP 135)
What rights are required for SMB lateral movement?|An account that is a member of the Administrators group on the target computer
How does UAC affect remote code execution via SMB?|Local admin accounts that are not RID 500 cannot run tools like PsExec on Windows Vista and later; domain users with admin rights can execute such tools
What is the significance of RID 500 in SMB lateral movement?|RID 500 local admin accounts can utilize tools like PsExec on machines regardless of UAC restrictions
What are named pipes in SMB used for?|Lateral movement operations - they enable operations from NULL session contexts to those requiring local admin privileges via the IPC$ share over TCP port 445
What does the svcctl named pipe facilitate?|Remote creation, starting, and stopping of services to execute commands (used by psexec.py and smbexec.py)
What does the atsvc named pipe support?|Remote creation of scheduled tasks for command execution (used by atexec.py)
What does the winreg named pipe provide?|Remote access to the Windows registry for querying and modifying registry keys and values
How does PsExec work?|It connects to the ADMIN$ share via SMB, uses the Service Control Manager to initiate PsExecsvc service, sets up a named pipe, and redirects console I/O through it
What advantage does PsExec have regarding the double-hop problem?|PsExec eliminates the double-hop problem because credentials are passed with the command and it generates an interactive logon session (Type 2)
What is SharpNoPSExec?|A tool that facilitates lateral movement by leveraging existing services on a target system without creating new ones or writing to disk
How does SharpNoPSExec minimize detection risk?|It queries existing services, finds stopped/disabled ones running as LocalSystem, temporarily modifies their binary path, executes the payload, then restores the original configuration
What criteria does SharpNoPSExec use to select services?|Start type set to disabled or manual, current status of stopped, and running with LocalSystem privileges
What is NimExec?|A fileless remote command execution tool that exploits the Service Control Manager Remote Protocol (MS-SCMR) using custom-crafted RPC packets over SMB
How does NimExec differ from traditional tools?|It manually crafts network packets instead of using WinAPI calls, avoids OS-specific functions, and uses Nim's cross-compilation capabilities
How can Reg.exe be used for lateral movement?|By modifying the Image File Execution Options registry key to set a debugger for a commonly used program, causing a payload to execute when that program is launched
What is psexec.py from Impacket?|A Python alternative to PsExec that creates a remote service by uploading an executable to the ADMIN$ share and establishes communication through a named pipe
How does smbexec.py differ from psexec.py?|It runs commands without uploading files, communicating exclusively over TCP port 445, making it a quieter alternative
What does services.py in Impacket do?|Interacts with Windows services using the MSRPC interface - allows starting, stopping, deleting, creating, listing, and modifying services
How does atexec.py work?|It uses the Windows Task Scheduler service via the atsvc SMB pipe to remotely create and execute scheduled tasks, sending output to a file accessed via the ADMIN$ share
What requirement does atexec.py have for proper functioning?|The clocks on both attacking and target PCs must be synchronized down to the exact minute
What registry key controls insecure guest authentication for SMB?|HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\AllowInsecureGuestAuth
What is WMI?|Windows Management Instrumentation - a standardized way to interact with system management information, manage devices and applications, useful for automation, monitoring, and scripting
What ports does WMI use?|TCP port 135 for initial connection and dynamically allocated ports in range 49152-65535 for data exchange
What rights are required for remote WMI operations?|By default, only members of the Administrators group can perform remote WMI operations
What are some key WMI classes used for system management?|Win32_OperatingSystem (OS details), Win32_Process (process management), Win32_Service (services), Win32_ComputerSystem (system info)
What is the status of the WMIC command-line utility?|Deprecated as of Windows 10 version 21H1, replaced by PowerShell for WMI tasks (but WMI itself remains unaffected)
How does NetExec's WMI command execution differ from Impacket's wmiexec.py?|NetExec can retrieve command output using WMI rather than SMB, so it works even if port 445 is blocked
What is WinRM?|Windows Remote Management - Microsoft's implementation of WS-Management protocol for secure remote communication using web services
What ports does WinRM use?|TCP port 5985 for HTTP and 5986 for HTTPS
Who can use WinRM by default?|Members of the Remote Management Users group have the necessary access
What is the difference between Invoke-Command and Enter-PSSession?|Invoke-Command executes commands remotely and returns results; Enter-PSSession establishes an interactive remote PowerShell session
What is winrs?|Windows Remote Shell - a command-line tool for executing commands on a remote Windows machine using WinRM
What is the double-hop problem in WinRM?|When connected to a remote machine via WinRM, attempting to use that session to connect to a third machine fails because credentials are not forwarded
How can you work around the double-hop problem in WinRM?|Use Rubeus within the remote session to forge a ticket and import it for further authentication
What is JEA (Just Enough Administration)?|A security technology that provides delegated administration for PowerShell, allowing creation of endpoints with tailored roles ensuring users can only execute predefined commands
What is Evil-WinRM?|A Ruby-based tool that facilitates interaction with WinRM from Linux, offering an interface for executing commands and managing Windows systems remotely
What features does Evil-WinRM support beyond basic command execution?|DLL loading, Donut payload loading, Invoke-Binary, AMSI bypass, file upload/download, and loading PowerShell scripts
What is Windows PowerShell Web Access?|A web-based interface for accessing PowerShell sessions remotely through a browser, typically available at /pswa on port 80 or 443
Why might you use Base64 output in PowerShell Web Access?|Because PowerShell Web Access connects to the target machine for each line, making large file retrieval slow - Base64 encoding loads faster
What is DCOM?|Distributed Component Object Model - a Microsoft technology extending COM to support communication among objects over a network using RPC over TCP/IP
What ports does DCOM use?|Port 135 for initial communication and dynamic ports in range 49152-65535 for subsequent interactions
What are the three key identifiers for DCOM objects?|CLSID (Class Identifier - unique GUID), ProgID (Programmatic Identifier - optional friendly name), AppID (Application Identifier - configuration details)
What group memberships are required for DCOM lateral movement?|Membership in the Distributed COM Users group or the Administrators group
What is the MMC20.Application DCOM object used for?|Remote interaction with Microsoft Management Console, enabling command execution and administrative task management
Why is MMC20.Application execution through COM likely to trigger alerts?|Because execution of mmc.exe through COM is highly unusual and difficult to mask as benign activity
What are ShellWindows and ShellBrowserWindow DCOM objects?|Objects that facilitate remote interaction with Windows Explorer instances for file operations and command execution
How do you instantiate ShellWindows/ShellBrowserWindow objects since they lack a ProgID?|Using Type.GetTypeFromCLSID method in .NET along with Activator.CreateInstance to create an instance via CLSID
What is dcomexec.py?|An Impacket tool providing an interactive shell on remote Windows hosts using DCOM endpoints (MMC20, ShellWindows, ShellBrowserWindow), operating over TCP port 445
What DCOM objects does dcomexec.py support?|MMC20.Application, ShellWindows, and ShellBrowserWindow
What is SSH?|Secure Shell - an encrypted protocol for remote system management, widely used for secure text-based administration and file transfers
What is the default port for SSH?|TCP port 22
Who can authenticate via SSH on Windows by default?|By default, the SSH server allows all user accounts to interact with SSH even if no specific privileges are configured
What limitation exists with SSH private/public key authentication?|It won't allow network-based authentication, limiting the user to local interaction only
What file permission issue can prevent SSH private key authentication on Windows?|If the private key file has too permissive rights (e.g., BUILTIN\Users can read), SSH will refuse to use it
What is the purpose of remote services in IT environments?|Remote management, resource sharing, collaboration, and efficiency - reducing the need for physical presence
What types of credentials can be used for lateral movement?|Passwords, NTLM hashes (Pass the Hash), NTLMv2 hashes (NTLM Relay), AES256 keys (via Rubeus/Mimikatz), and Kerberos tickets
What are the main types of remote services exploitable for lateral movement per MITRE ATT&CK T1021?|RDP, SMB/Windows Shares, WMI, WinRM, DCOM, and SSH
What common enumeration methods are used to discover remote services?|Port scanning, service banner analysis, and Active Directory querying
What are the key detection strategies for lateral movement?|Monitoring authentication logs, honeypots and deception, network traffic analysis, and Endpoint Detection and Response (EDR)
What Windows Event IDs are useful for monitoring login activity?|Event ID 4624 (successful logon) and 4625 (failed logon)
What is a honeypot in cybersecurity?|An artificial environment designed to mimic real systems to observe and analyze attacker behavior
What are the key prevention strategies for lateral movement?|Network segmentation, least privilege principle, and zero trust architecture
What is network segmentation?|Dividing the network into smaller, isolated segments with strict access controls to restrict lateral movement
What is the least privilege principle?|Providing users and applications with only the essential permissions required to carry out their functions
What is zero trust architecture?|A security model where no entity is trusted by default and every access request must be verified and authenticated regardless of origin
How can you use chisel for pivoting in lateral movement?|Set up a SOCKS5 proxy on port 1080 in proxychains.conf, start a chisel reverse server on the attack host, and connect from the target with chisel client pointing to the server
What is Rubeus used for in lateral movement?|Forging Kerberos tickets (TGT), creating sacrificial processes with createnetonly, and importing tickets for Pass the Ticket attacks
What does the createnetonly option in Rubeus do?|Creates a sacrificial process with dummy credentials that can be used to import forged Kerberos tickets
What are some creative lateral movement opportunities to look for in Windows networks?|Development environments running code on accessible servers, applications loading DLLs from shared folders, MSSQL servers running queries from config files, domain-wide inventory software executing PowerShell
What should you do when encountering unknown networks for lateral movement?|Observe running services and how they interact, use creativity and imagination to identify opportunities, test all credentials against available services
How can firewalls and network segmentation affect lateral movement?|They may block direct access to servers, change default ports, restrict access to specific workstations, allow inbound access only from specific IPs, block outbound internet, and monitor traffic
How can you identify non-default service ports on Windows?|Use netstat -ano to find listening ports, then use tasklist /svc /FI "PID eq [PID]" to identify which service owns the port
