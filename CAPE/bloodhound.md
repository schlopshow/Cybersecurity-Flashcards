What is BloodHound?|An open-source tool used by attackers and defenders to analyze Active Directory domain security using graph theory to visually represent relationships between objects and identify attack paths
What type of data structure does BloodHound use to represent relationships?|Graph theory - mathematical structures that model pairwise relations between objects using nodes and edges
What are nodes in BloodHound's graph theory?|Active Directory objects such as users, groups, computers, etc.
What are edges in BloodHound's graph theory?|Relations between objects such as MemberOf, AdminTo, ForceChangePassword, etc.
What query language does BloodHound use to analyze relationships?|Cypher Query Language - Neo4j's graph query language similar to SQL but designed for graphs
What database does BloodHound use?|Neo4j - a graph database management system that uses a NoSQL graph data model with nodes and edges
What is Neo4j written in and what does it require to run?|Written in Java and requires a Java Virtual Machine (JVM)
What is SharpHound?|The official data collector tool for BloodHound, written in C# that runs on Windows systems with the .NET framework using native Windows API functions and LDAP queries
As of version 4.0, what additional environment does BloodHound support?|Azure (Microsoft cloud)
Who created BloodHound?|@_wald0, @harmj0y, and @CptJesus
What is BloodHound Enterprise?|An Attack Path Management solution by SpecterOps that continuously maps and quantifies Active Directory Attack Paths for enterprises
What is SharpHound Common?|One code base from which both FOSS SharpHound and SharpHound Enterprise are built
What does a shortest path mean in BloodHound?|The minimum number of hops (edges) needed to get from one node to another node in the graph
What does the default SharpHound collection method collect?|Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
What specific information does SharpHound collect by default?|Users and computers, AD security group membership, domain trusts, abusable permissions on AD objects, OU tree structure, Group Policy links, relevant AD object properties, local groups and privileges, user sessions, and all SPNs
What is required for SharpHound to collect local group membership and active sessions from domain-joined machines?|The user session running SharpHound must have Administrator rights on the target computer
What format does SharpHound output its data in?|A zip file containing JSON files (computers.json, domains.json, gpos.json, groups.json, ous.json, users.json)
Why is Neo4j version 5 not recommended for BloodHound?|It suffers from severe performance regression issues
What is the default Neo4j web console URL?|http://localhost:7474/
What are the default Neo4j credentials?|Username: neo4j, Password: neo4j
What port does Neo4j Bolt protocol use?|7687
What Neo4j configuration must be changed to allow remote connections?|Uncomment the line dbms.default_listen_address=0.0.0.0 in the neo4j.conf file
Where is the Neo4j configuration file located on Linux?|/etc/neo4j/neo4j.conf
How do you recover Neo4j credentials if you can't access the database?|Stop neo4j, uncomment dbms.security.auth_enabled=false in neo4j.conf, start neo4j, connect without credentials, set new password with ALTER USER query, then re-enable auth
What is the DCOnly collection method in SharpHound?|Collects data only from the domain controller without connecting to domain-joined Windows devices - includes users, computers, group memberships, trusts, permissions, OU structure, GPO, and AD object properties
What is the ComputerOnly collection method in SharpHound?|The opposite of DCOnly - only collects information from domain-joined computers such as user sessions and local groups
Why might you use DCOnly instead of Default collection method?|To avoid generating traffic to all workstations which could trigger SOC detection - DCOnly only generates traffic to the domain controller
What does the --computerfile option do in SharpHound?|Allows you to specify a file containing a list of specific computer names to enumerate instead of all domain computers
What does the --memcache option do in SharpHound?|Keeps the cache in memory and doesn't write it to disk, helping avoid detection
What does the --randomfilenames option do in SharpHound?|Generates random filenames for output including the zip file to avoid detection patterns
What does the --zippassword option do in SharpHound?|Password protects the output zip file with the specified password
What is the purpose of session loop collection in SharpHound?|Sessions are temporary and disappear after a user disconnects, so looping allows SharpHound to repeatedly check for sessions over a specified time period
What are the default loop duration and interval in SharpHound?|Default duration is 2 hours, default interval is 30 seconds
What does the --stealth option do in SharpHound?|Performs stealth data collection by only touching systems most likely to have user session data
How can you run SharpHound from a non-domain-joined system?|Use runas /netonly /user:DOMAIN\username to execute the application with specific domain credentials - the /netonly flag ensures network access using the provided credentials
What does runas /netonly NOT do?|It does not validate credentials - if wrong credentials are used, you'll only notice when trying to connect through the network
What is BloodHound.py?|A Python-based collector for BloodHound created by Dirk-jan Mollema, based on Impacket, that allows collecting Active Directory information from Linux
What dependencies does BloodHound.py require?|impacket, ldap3, and dnspython
What authentication methods does BloodHound.py support?|Username and password, NTLM hash, AES key, or ccache file - defaults to Kerberos with NTLM fallback
What does the --nameserver option do in BloodHound.py?|Allows specifying an alternative DNS name server for queries when the system DNS server is not the domain DNS server
Why is Kerberos authentication preferred over NTLM when collecting data?|Using Kerberos makes traffic look more normal since it is the default authentication method for Windows
What is required for Kerberos authentication with BloodHound.py?|The host must resolve the domain FQDN, DNS must be configured to the target, and time must be synchronized between KDC and attacker host
What does BloodHound.py output by default compared to SharpHound?|BloodHound.py produces JSON files but does not zip them by default (use --zip option to compress)
What is the Graph Drawing Area in BloodHound?|The main area where BloodHound displays nodes and their relationships using edges, allowing interaction like moving objects, zooming, and clicking nodes
What does "Set as Starting Node" do in BloodHound?|Sets the selected node as the starting point in the pathfinding tool
What does "Set as Ending Node" do in BloodHound?|Sets the selected node as the target node in the pathfinding tool
What does "Shortest Paths to Here" do in BloodHound?|Performs a query to find all shortest paths from any arbitrary node in the database to the selected node
What does "Shortest Paths to Here from Owned" do?|Finds attack paths to the selected node from any node marked as owned
What does "Mark Group as Owned" do in BloodHound?|Internally sets the node as owned in the neo4j database, which can be used with queries like "Shortest paths to here from Owned"
What does "Mark/Unmark Group as High Value" do?|Marks nodes as high value (some like Domain Admins are marked by default) for use with queries like "shortest paths to high-value assets"
What information does the edge help menu in BloodHound contain?|Information, abuse examples, opsec considerations, and references on how to abuse every single edge
What node types can you prepend to searches in BloodHound?|AD: Group, Domain, Computer, User, OU, GPO, Container. Azure: AZApp, AZRole, AZDevice, AZGroup, AZKeyVault, AZManagementGroup, AZResourceGroup, AZServicePrincipal, AZSubscription, AZTenant, AZUser, AZVM
What is the Pathfinding feature in BloodHound?|A search bar feature that finds attack paths between two given nodes, with the ability to filter out specific edges
What does the Export Graph option do in BloodHound?|Saves the current graph in JSON format for later import, or as a PNG image
What does the Node Collapse Threshold setting control?|Collapses nodes at the end of paths that only have one relationship (0 to disable, default 5)
What does Query Debug Mode do in BloodHound?|Shows raw Cypher queries in the Raw Query Box so you can see the queries BloodHound uses behind the scenes
What keyboard shortcut cycles through node label display settings?|CTRL
What does the Spacebar shortcut do in BloodHound?|Brings up the spotlight window listing all currently drawn nodes - clicking an item zooms to and highlights that node
What does the Backspace shortcut do in BloodHound?|Returns to the previous graph result rendering
What does the S shortcut do in BloodHound?|Toggles the expansion or collapse of the information panel below the search bar
What does the "Warming Up Database" option do?|Puts the entire database into memory to significantly speed up queries, though it can take time for large databases
What are the Active Directory node types in BloodHound?|Users, Groups, Computers, Domains, GPOs, OUs, and Containers
What is a User node in BloodHound?|Objects representing individuals who can log in to a network and access resources with unique usernames and passwords
What is a Group node in BloodHound?|Used to organize users and computers into logical collections for assigning permissions to resources
What is a Computer node in BloodHound?|Objects representing devices that connect to the network with unique names and identifiers
What is a Domain node in BloodHound?|A logical grouping of network resources providing centralized administration and security
What is a GPO node in BloodHound?|Group Policy Objects that define and enforce policies and settings for users and computers within an AD domain
What is an OU node in BloodHound?|Organizational Units - containers within a domain for grouping and managing resources with administrative control
What is a Container node in BloodHound?|Similar to OUs but used for non-administrative/organizational purposes without the same level of administrative control
What categories of information does the User node info tab display?|Overview, Node Properties, Extra Properties, Group Membership, Local Admin Rights, Execution Rights, Outbound Object Control, and Inbound Control Rights
What does the Execution Rights section show for a node?|Permissions and privileges to execute specific actions like RDP access, DCOM execution, SQL Admin Rights
What does Outbound Object Control show?|The permissions and privileges that a user, group, or computer has over other objects in the AD environment
What does Inbound Control Rights show?|The permissions and privileges of other objects over a specific AD object
What unique sections does a Computer node have?|Local Admins, Inbound Execution Rights, and Outbound Execution Rights
What does the Local Admins section show for a Computer node?|Users, groups, and computers granted local administrator privileges on that specific computer
What unique section does a Group node have?|Group Members - refers to users, groups, and computer members of the specific group
What unique sections does a Domain node have?|Foreign Members, Inbound Trusts, and Outbound Trusts
What are Foreign Members in a Domain node?|Users or groups that belong to a different domain or forest than the one being analyzed
What are Inbound Trusts?|Trust relationships where another domain or forest trusts the current domain, allowing users from the trusted domain to access current domain resources
What are Outbound Trusts?|Trust relationships where the current domain trusts another domain, allowing current domain users to access trusted domain resources
What does the Map OU Structure option show?|A high-level overview of how the Active Directory is organized
What unique sections do OU and Container nodes have?|Affecting GPOs and Descendant Objects
What unique section does a GPO node have?|Affected Objects - the users, groups, and computers affected by the specific GPO
What are edges in BloodHound?|Lines connecting two objects representing privileges, permissions, and trust relationships, with direction indicating the direction of the relationship
What does the AdminTo edge mean?|The source node has administrative privileges on the target node
What does the MemberOf edge mean?|The source node is a member of the target group
What does the HasSession edge mean?|The target computer has an active session from the source user
What does the ForceChangePassword edge mean?|The source can change the target user's password without knowing the current password
What does the AddMembers edge mean?|The source can add members to the target group
What does the AddSelf edge mean?|The source can add itself to the target group
What does the CanRDP edge mean?|The source can connect to the target via Remote Desktop Protocol
What does the CanPSRemote edge mean?|The source can connect to the target via PowerShell Remoting
What does the ExecuteDCOM edge mean?|The source can execute commands on the target via DCOM
What does the DCSync edge mean?|The source can perform the DCSync attack to replicate domain credentials
What does the GenericAll edge mean?|The source has full control over the target object
What does the GenericWrite edge mean?|The source can write to any non-protected attribute on the target
What does the WriteOwner edge mean?|The source can change the owner of the target object
What does the WriteSPN edge mean?|The source can write the ServicePrincipalName attribute on the target
What does the Owns edge mean?|The source is the owner of the target object
What does the AddKeyCredentialLink edge mean?|The source can add key credentials to the target for Shadow Credentials attack
What does the ReadLAPSPassword edge mean?|The source can read the LAPS password for the target computer
What does the ReadGMSAPassword edge mean?|The source can read the Group Managed Service Account password
What does the AllExtendedRights edge mean?|The source has all extended rights on the target
What does the AllowedToDelegate edge mean?|The source is allowed to delegate credentials to the target
What does the AllowedToAct edge mean?|The source is allowed to act on behalf of the target (resource-based constrained delegation)
What does the AddAllowedToAct edge mean?|The source can modify the target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute
What does the WriteDacl edge mean?|The source can modify the DACL (access control list) of the target object
What does the WriteAccountRestrictions edge mean?|The source can write account restriction attributes on the target
What tabs are available when right-clicking an edge for help?|Info, Abuse Info, Opsec Considerations, and References
What does the Opsec Considerations tab provide?|Information about potential risks an attack may pose and how easy it would be to detect the attack being executed
What query does BloodHound perform upon successful login?|Find all Domain Admins - displays users belonging to the Domain Admins group
What is the first step when analyzing BloodHound data for a domain?|Start with overall domain analysis by searching for the domain name, then check Domain Users group rights
Why is checking the Domain Users group important?|Every user in the domain inherits any rights granted to this group, so minor misconfigurations could have major security effects
What does the "Find Shortest Paths to Domain Admins" pre-built query do?|Returns paths from various nodes to the Domain Admins group, showing potential attack paths
What does the "Find Principals with DCSync Rights" query show?|Accounts that can perform the DCSync attack
What does "Users with Foreign Domain Group Membership" show?|Users belonging to groups in other domains, useful for cross-trust attacks
What does "Shortest Paths from Kerberoastable Users" show?|Shortest path to Domain Admins from users that can be Kerberoasted
What does "Shortest Path from Owned Principals" show?|How far you can go from any users/computers marked as owned
What does "Shortest Paths to High-Value Targets" show?|Shortest paths to objects BloodHound considers high value or that you've marked as high value
How does BloodHound indicate sessions in the GUI?|In the Database Info tab and within node info for users, groups, or computers showing session counts
What does the Mark as Owned feature do?|Marks a node with a skull icon indicating it is under your control, useful for identifying further attack paths from compromised nodes
What is the Cypher query language based on?|ASCII art patterns, making it highly visual and easy to read, showing patterns of nodes and relationships
What does the MATCH keyword do in Cypher?|Used before describing the search pattern for finding one or more nodes or relationships
What does the WHERE keyword do in Cypher?|Adds more constraints to specific patterns or filters out unwanted patterns
What does the RETURN keyword do in Cypher?|Specifies the results format and organizes the resulting data
How are nodes represented in Cypher syntax?|With parentheses around attributes and information, e.g., (n:User)
How are relationships represented in Cypher syntax?|With dashes and arrows with the relationship type in brackets, e.g., -[r:MemberOf]->
What does a Label do in Cypher?|Groups nodes based on properties or characteristics, denoted by a colon, e.g., :User
What does a Property do in Cypher?|Stores additional information about a node or relationship, denoted by curly braces, e.g., {name:"PETER@DOMAIN.HTB"}
What does the depth notation 1..* mean in a Cypher relationship?|Minimum depth of 1 and maximum depth of any number - matches paths of any depth
What does the shortestPath function do in Cypher?|Finds the shortest path between two nodes in a graph
What does the allshortestpaths function do in Cypher?|Returns every single shortest path relationship available between nodes, not just one
What does the CONTAINS keyword do in Cypher?|Checks if a string contains a specified substring
What does the =~ operator do in Cypher?|Checks if a string matches a regular expression
What does (?i) do in a Cypher regular expression?|Tells the regular expression engine to ignore case
Where is the customqueries.json file located on Windows?|AppData\Roaming\bloodhound\customqueries.json
Where is the customqueries.json file located on Linux?|/home/<username>/.config/bloodhound/customqueries.json or /root/.config/bloodhound/customqueries.json
What does the config.json file hold in BloodHound?|Current BloodHound configuration including performance options and included edges
Where are BloodHound's pre-built queries loaded from?|The PrebuiltQueries.json file in the BloodHound directory
How can you make custom queries more dynamic in BloodHound?|Use multiple query stages where the first query provides a selection list and the result is passed as $result variable to the second query
What tool can be used if BloodHound queries don't show results for a compromised user?|PowerView or SharpView to display user privileges over other AD objects
What is BlueHound?|An open-source tool that helps blue teams identify critical security issues by combining user permissions, network access, and vulnerability information to reveal attacker paths
What are BlueHound's main features?|Full Automation (collection, analysis, reporting), Community Driven (sharing configurations), Easy Reporting, and Easy Customization
What does BlueHound automate?|The entire cycle of SharpHound data collection, analysis, and reporting with scheduling options (daily, weekly, monthly)
What is PlumHound?|A tool that wraps BloodHound's Neo4j cypher queries into operations-consumable reports for identifying and hardening AD configuration vulnerabilities
What does PlumHound's Path Analyzer (-ap) option do?|Iterates through all paths between a start and end node to identify which relationships to remove to break attack paths
What are some things blue teams should monitor using BloodHound?|Administrators with sessions on non-domain machines, dangerous Domain Users privileges, paths from Kerberoastable users, users with excessive privileges, users not requiring pre-authentication, users with excessive sessions
What is ImproHound?|A tool that helps identify AD attack paths by breaking down the AD tier model using BloodHound data
What is GoodHound?|A tool that helps prioritize remediation efforts by determining the busiest paths to high-value targets using BloodHound data
What is AzureHound?|A Go binary that collects data from AzureAD and AzureRM via the MS Graph and Azure REST APIs for use with BloodHound
What authentication methods does AzureHound support?|Username and Password, JWT, Refresh Token, Service Principal Secret, and Service Principal Certificate
What are the Azure node types in BloodHound?|AZTenant, AZUser, AZGroup, AZApp, AZSubscription, AZResourceGroup, AZVM, AZDevice, AZServicePrincipal
What is an AZTenant node?|A dedicated instance of Azure AD that an organization owns and uses to manage access to applications and resources
What is an AZServicePrincipal node?|A security identity used by applications and services to access resources in Azure
What does the AZGlobalAdmin edge mean?|The principal is assigned to the Global Administrator role in Azure AD
What does the AZResetPassword edge mean?|Allows a user to reset passwords for other users in Azure
What does the AZUserAccessAdministrator edge mean?|Allows a user to manage user access to Azure resources
What does the AZVMAdminLogin edge mean?|Allows a user to log in as a VM administrator
What does the AZContributor edge mean?|The principal has been assigned the Contributor role allowing them to manage all resource types within that scope
What does the AZExecuteCommand edge mean?|The principal has permission to execute a command on a virtual machine
What does the AZGetSecrets edge mean?|The principal has permission to retrieve secrets from Azure Key Vault
What does the AZGetKeys edge mean?|The principal has permission to retrieve keys from Azure Key Vault
What does the AZGetCertificates edge mean?|The principal has permission to retrieve certificates from Azure Key Vault
What does the AZOwns edge mean?|The principal owns a resource in Azure
What does the AZManagedIdentity edge mean?|A resource has an associated managed identity allowing it to authenticate with other Azure services
What does the AZAddMembers edge mean?|The principal can add members to a group or directory role in Azure
What does the AZKeyVaultContributor edge mean?|The principal can manage key vaults at the resource group or resource level
What is PowerZure?|A PowerShell framework created to assess and exploit resources within Microsoft Azure, similar to PowerView for Active Directory
What can PowerZure do?|Info gathering (users, groups, roles, managed identities, key vaults, VMs), operational tasks (add group members, reset passwords, execute commands on VMs, create backdoors, export key vault content)
What is Azure Key Vault?|A cloud service for securely storing and accessing secrets like API keys, passwords, certificates, and cryptographic keys
What limitation exists with Azure enumeration regarding user permissions?|By default, Azure users don't have privilege to read all Azure objects - objects may not appear in enumeration if the authenticated user lacks read rights
What is TheEdgeMaker?|A PowerShell script that automatically creates Azure Edges for use in BloodHound for practice purposes (creates weak configurations - not for production use)
What is the default limitation users face when enumerating Azure with AzureHound?|Users may not have read access to all Azure objects like subscriptions, VMs, and resource groups, requiring privilege escalation to enumerate further
How does BloodHound handle duplicate data when uploading?|BloodHound will not duplicate data but will add any new data not already present in the database
What is the Transitive Object Control option in BloodHound?|Shows all objects over which a node has control through direct and inherited permissions
What communication protocols does SharpHound use for different collection methods?|LDAP for AD queries, RPC and SMB for computer-based methods like session and local group enumeration
Why are sessions important in Active Directory security assessments?|They reveal where users are actively logged in, helping identify which computers to compromise to achieve objectives like accessing privileged user credentials
