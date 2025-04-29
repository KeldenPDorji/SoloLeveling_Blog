---
title: "Active Directory"
description: "Active Directory is a proprietary directory service developed by Microsoft® to provide secure access to corporate networks."
pubDate: "April 27 2025"
heroImage: "/ad.jpg"
---

# Active Directory Notes: Structure, History, and Terminology

## Why Active Directory?

Active Directory (AD) is a directory service for Windows network environments that provides a hierarchical structure for centralized management of an organization's resources. It's estimated that around 95% of Fortune 500 companies run Active Directory, making it a key target for attackers.

### Key Points about Active Directory:
- Provides authentication and authorization within Windows domains
- Distributed, hierarchical structure for managing users, computers, groups, etc.
- Highly scalable - supports millions of objects per domain
- Not always "secure by default" due to backward compatibility requirements
- Even basic AD user accounts can enumerate most objects within AD

### Security Implications:
- Increasingly targeted by attackers and ransomware operators
- Critical vulnerabilities like PrintNightmare (CVE-2021-34527) and Zerologon (CVE-2020-1472)
- Many attacks require only a standard domain user to obtain administrative control
- AD's readable nature to standard users makes thorough enumeration possible

## History of Active Directory

- **Early Foundations**: LDAP (foundation of AD) introduced in RFCs as early as 1971
- **Predecessors**: X.500 organizational unit concept; Novell Directory Services (1993)
- **First Introduction**: Mid-1990s
- **Windows Integration**: First included in Windows Server 2000
- **Evolution**:
  - Windows Server 2003: Extended functionality and Forest feature
  - Windows Server 2008: Active Directory Federation Services (ADFS) introduced
  - Windows Server 2016: Cloud migration capabilities, security enhancements (gMSA)

## Active Directory Structure

AD is organized in a hierarchical tree structure:

```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│ ├── GPOs
│ └── OU
│ └── EMPLOYEES
│ ├── COMPUTERS
│ │ └── FILE01
│ ├── GROUPS
│ │ └── HQ Staff
│ └── USERS
│ └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

- **Forest**: Top-level container, security boundary where all objects are under administrative control
- **Domain**: Structure containing objects (users, computers, groups) that are accessible
- **Organizational Units (OUs)**: Containers for objects and sub-OUs, allowing assignment of group policies
- **Trust Relationships**: Connect multiple domains or forests, enabling cross-domain resource access

## Active Directory Terminology

### Basic Objects and Identifiers:
- **Object**: Any resource in AD (users, OUs, printers, domain controllers, etc.)
- **Attributes**: Characteristics of objects (hostname, DNS name, etc.)
- **Schema**: Blueprint defining object types and attributes
- **GUID** (Global Unique Identifier): Unique 128-bit value assigned to all AD objects
- **SID** (Security Identifier): Unique identifier for security principals or groups

### Naming Conventions:
- **Distinguished Name (DN)**: Full path to an object (e.g., `cn=bjones,ou=IT,ou=Employees,dc=inlanefreight,dc=local`)
- **Relative Distinguished Name (RDN)**: Single component identifying an object (e.g., `bjones`)
- **sAMAccountName**: User's logon name (e.g., `bjones`) - must be unique and ≤20 characters
- **userPrincipalName**: User identifier in format `username@domain` (e.g., `bjones@inlanefreight.local`)

### Domain Controller Roles:
- **FSMO Roles** (Flexible Single Master Operation):
  - Schema Master (1 per forest)
  - Domain Naming Master (1 per forest)
  - RID Master (1 per domain)
  - PDC Emulator (1 per domain)
  - Infrastructure Master (1 per domain)
- **Global Catalog**: Stores all objects in an AD forest (full copy of current domain, partial copy of other domains)
- **RODC** (Read-Only Domain Controller): Contains read-only AD database

### Security Mechanisms:
- **Security Principals**: Entities that can be authenticated (users, computers, services)
- **ACL** (Access Control List): Collection of Access Control Entries
- **ACE** (Access Control Entry): Identifies trustee and lists access rights
- **DACL** (Discretionary Access Control List): Defines granted/denied access
- **SACL** (System Access Control List): Logs access attempts to secured objects
- **AdminSDHolder**: Manages ACLs for privileged group members
- **adminCount**: Attribute determining if a user is protected by SDProp process

### Special AD Components:
- **SYSVOL**: Folder storing public files like policies and scripts
- **NTDS.DIT**: Database file storing AD data including password hashes
- **Tombstone**: Container for deleted AD objects
- **AD Recycle Bin**: Feature to facilitate recovery of deleted objects
- **dsHeuristics**: Attribute for forest-wide configuration settings

### Administrative Tools:
- **ADUC** (Active Directory Users and Computers): GUI console for managing AD objects
- **ADSI Edit**: Advanced GUI tool for deeper AD management

## Additional Concepts
- **Replication**: Process of synchronizing AD objects between Domain Controllers
- **SPN** (Service Principal Name): Uniquely identifies service instances
- **GPO** (Group Policy Object): Collections of policy settings
- **FQDN** (Fully Qualified Domain Name): Complete name for a computer or host

This knowledge is essential for both attacking and defending Active Directory environments, as understanding the structure helps identify potential misconfigurations and vulnerabilities.

# Active Directory Notes: Objects, Functionality, Authentication

## Active Directory Objects

Objects are any resources present within an Active Directory environment. These include:

### User Objects
- **Definition**: Users within the organization's AD environment
- **Properties**: Leaf objects (cannot contain other objects)
- **Security**: Considered security principals with SIDs and GUIDs
- **Attributes**: Display name, last login time, password change date, email, description, manager, etc.
- **Importance**: Prime target for attackers since even low-privileged users can enumerate domain resources

### Contact Objects
- **Definition**: Represents external users (like vendors or customers)
- **Properties**: Leaf objects, NOT security principals (no SID, only GUID)
- **Attributes**: First name, last name, email, telephone number, etc.

### Printer Objects
- **Definition**: Points to printers accessible within the AD network
- **Properties**: Leaf objects, NOT security principals (no SID, only GUID)
- **Attributes**: Printer name, driver information, port number, etc.

### Computer Objects
- **Definition**: Any computer joined to the AD network (workstations/servers)
- **Properties**: Leaf objects, ARE security principals (have SID and GUID)
- **Security**: Full access to a computer (as NT AUTHORITY\SYSTEM) grants similar rights to a standard domain user

### Shared Folder Objects
- **Definition**: Points to a shared folder on a specific computer
- **Properties**: NOT security principals (only GUID)
- **Access Control**: Can be accessible to everyone, authenticated users only, or specific users/groups
- **Attributes**: Name, location, security access rights

### Group Objects
- **Definition**: Container objects that can contain users, computers, and even other groups
- **Properties**: ARE security principals (have SID and GUID)
- **Purpose**: Used to manage user permissions and access to other securable objects
- **Nested Groups**: Groups added as members of other groups (can lead to unintended rights)
- **Attributes**: Name, description, membership, group memberships

### Organizational Units (OUs)
- **Definition**: Containers that store similar objects for administrative purposes
- **Usage**: Administrative delegation without granting full admin rights
- **Functions**: 
  - Can be used to delegate specific tasks (password resets, user creation)
  - Managing Group Policy for subsets of users and groups
  - Hierarchical organization (e.g., top-level "Employees" OU with department child OUs)
- **Attributes**: Name, members, security settings

### Domain Objects
- **Definition**: The structure of an AD network
- **Contents**: Users, computers, groups, OUs
- **Properties**: Has its own database and policies

### Domain Controllers
- **Definition**: The "brains" of an AD network
- **Functions**: Handle authentication requests, verify users, control resource access
- **Security**: Validates access requests and enforces security policies
- **Storage**: Stores information about all domain objects

### Other Object Types
- **Sites**: Sets of computers across subnets connected via high-speed links
- **Built-in**: Container holding default groups in an AD domain
- **Foreign Security Principals**: Objects representing security principals from trusted external forests

## Active Directory Functionality

### FSMO (Flexible Single Master Operation) Roles

| Role | Description |
|------|-------------|
| Schema Master | Manages read/write copy of the AD schema defining object attributes |
| Domain Naming Master | Manages domain names, prevents duplicate domain names in same forest |
| Relative ID (RID) Master | Assigns RID blocks to DCs, ensures unique object SIDs |
| PDC Emulator | Authoritative DC for authentication, password changes, GPOs, and time |
| Infrastructure Master | Translates GUIDs, SIDs, and DNs between domains |

### Domain and Forest Functional Levels
Functional levels determine features available in AD DS and compatible Windows Server versions:

#### Key Domain Functional Levels:
- **Windows 2000 native**: Universal groups, group nesting/conversion, SID history
- **Windows Server 2003**: Domain management tools, lastLogonTimestamp attribute
- **Windows Server 2008**: DFS replication, AES support for Kerberos, fine-grained password policies
- **Windows Server 2008 R2**: Authentication mechanism assurance, Managed Service Accounts
- **Windows Server 2012**: Enhanced Kerberos features (claims, compound authentication, armoring)
- **Windows Server 2012 R2**: Protected Users group protections, Authentication Policies/Silos
- **Windows Server 2016**: Smart card required for interactive logon, new Kerberos and credential protection

#### Key Forest Functional Levels:
- **Windows Server 2003**: Forest trusts, domain renaming, RODCs
- **Windows Server 2008 R2**: Active Directory Recycle Bin
- **Windows Server 2016**: Privileged access management using Microsoft Identity Manager

### Trusts
Trusts establish authentication paths between domains or forests:

#### Trust Types:
- **Parent-child**: Two-way transitive trust between domains in same forest
- **Cross-link**: Trust between child domains to speed up authentication
- **External**: Non-transitive trust between separate domains in separate forests
- **Tree-root**: Two-way transitive trust between forest root domain and new tree root domain
- **Forest**: Transitive trust between two forest root domains

#### Trust Properties:
- **Transitive**: Trust extends to objects that the child domain trusts
- **Non-transitive**: Only the child domain itself is trusted
- **Bidirectional**: Users from both trusting domains can access resources
- **One-way**: Only users in trusted domain can access resources in trusting domain

## Authentication Protocols

### Kerberos
- **Role**: Default authentication protocol for domain accounts since Windows 2000
- **Characteristics**: Stateless, ticket-based (no password transmission)
- **Components**:
  - **KDC (Key Distribution Center)**: Issues tickets, runs on Domain Controllers
  - **TGT (Ticket Granting Ticket)**: Initial ticket received after authentication
  - **TGS (Ticket Granting Service)**: Ticket for accessing specific services
- **Process**:
  1. User encrypts timestamp with password and sends to KDC
  2. KDC verifies user, creates TGT encrypted with krbtgt account key
  3. User presents TGT to request service-specific TGS ticket
  4. TGS ticket is encrypted with service's NTLM password hash
  5. User presents TGS to service for access
- **Port**: 88 (TCP/UDP)

### DNS (Domain Name System)
- **Role**: Resolves hostnames to IP addresses, helps clients locate domain controllers
- **Components**:
  - **SRV Records**: Identify services on the network (DCs, file servers, etc.)
  - **Dynamic DNS**: Automatically updates DNS records when IP addresses change
- **Process**: Client queries DNS to locate domain controller, then gets its IP address
- **Port**: 53 (UDP primarily, falls back to TCP)
- **Examples**:
  ```powershell
  # Forward DNS lookup
  nslookup INLANEFREIGHT.LOCAL
  
  # Reverse DNS lookup
  nslookup 172.16.6.5
  
  # Finding IP of a host
  nslookup ACADEMY-EA-DC01
  ```

### LDAP (Lightweight Directory Access Protocol)
- **Role**: Directory lookup protocol for authentication and querying AD
- **Version**: LDAP v3 (RFC 4511)
- **Ports**: 389 (LDAP), 636 (LDAPS - LDAP over SSL)
- **Authentication Types**:
  - **Simple Authentication**: Anonymous, unauthenticated, or username/password
  - **SASL Authentication**: Uses other services (e.g., Kerberos) for binding to LDAP
- **Security**: Transmits in cleartext by default; should use TLS encryption

### MSRPC (Microsoft Remote Procedure Call)
- **Role**: Enables client-server communication for Windows systems
- **Key Interfaces**:
  - **lsarpc**: Manages local security policy, controls audit policy
  - **netlogon**: Authenticates users and services in the domain
  - **samr**: Manages domain account database (users, groups)
  - **drsuapi**: Implements Directory Replication Service protocol
    - Can be abused to create copy of NTDS.dit file containing password hashes


# Active Directory Authentication and Account Management Notes

## NTLM Authentication

### Hash Types and Authentication Protocols Comparison

| Hash/Protocol | Cryptographic technique | Mutual Authentication | Message Type | Trusted Third Party |
|---------------|-------------------------|----------------------|--------------|---------------------|
| NTLM | Symmetric key cryptography | No | Random number | Domain Controller |
| NTLMv1 | Symmetric key cryptography | No | MD4 hash, random number | Domain Controller |
| NTLMv2 | Symmetric key cryptography | No | MD4 hash, random number | Domain Controller |
| Kerberos | Symmetric & asymmetric cryptography | Yes | Encrypted ticket using DES, MD5 | Domain Controller/KDC |

### LM Hash
- Oldest password storage mechanism (1987, OS/2 operating system)
- Stored in SAM database (local) and NTDS.DIT database (domain controller)
- Limited to 14 characters maximum
- Passwords converted to uppercase (not case-sensitive)
- Keyspace limited to 69 characters
- Splits passwords into two 7-character chunks before hashing
- Each chunk used to create DES keys to encrypt "KGS!@#$%"
- Results in easily crackable hashes
- Can be disabled via Group Policy
- Format example: `299bd128c1101fd6`

### NT Hash (NTLM)
- Used on modern Windows systems
- Stored in SAM database or NTDS.DIT database
- Algorithm: `MD4(UTF-16-LE(password))`
- Supports full Unicode character set (65,536 characters)
- Stronger than LM but still vulnerable to offline brute-force attacks
- 8-character NTLM can be brute-forced in under 3 hours with GPU
- Vulnerable to pass-the-hash attacks
- Format example full hash: `username:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::`
  - First part is username
  - 500 is the Relative Identifier (RID)
  - Third part is LM hash
  - Fourth part is NT hash

### NTLM Authentication Process
- Challenge-response authentication protocol using three messages:
  1. Client sends `NEGOTIATE_MESSAGE` to server
  2. Server responds with `CHALLENGE_MESSAGE` 
  3. Client sends `AUTHENTICATE_MESSAGE`
- Neither LANMAN nor NTLM uses a salt in hashing

### NTLMv1
- Challenge/response protocol for network authentication
- Uses both NT and LM hash
- Server sends 8-byte random challenge, client returns 24-byte response
- Cannot be used for pass-the-hash attacks
- Algorithm: `response = DES(K1,C) | DES(K2,C) | DES(K3,C)`
  - C = 8-byte server challenge
  - K1|K2|K3 = LM/NT-hash with padding

### NTLMv2
- Introduced in Windows NT 4.0 SP4
- Default authentication since Windows Server 2000
- Hardened against spoofing attacks
- Sends two responses to server challenge
- Includes client challenge, timestamps, and domain name in calculation
- Algorithm includes:
  - HMAC-MD5 hash of user credentials
  - 8-byte server challenge
  - Variable-length client challenge with timestamp

### Domain Cached Credentials (MSCache2)
- Allows login when domain controller is unavailable
- Hosts save last ten domain user hashes that logged in
- Stored in registry: `HKEY_LOCAL_MACHINE\SECURITY\Cache`
- Cannot be used for pass-the-hash attacks
- Very slow to crack even with powerful hardware
- Format: `$DCC2$10240#username#hash`

## User and Machine Accounts

### Local Accounts
- Stored on individual servers/workstations
- Rights apply only to that specific host
- Default accounts include:
  - **Administrator** (SID: S-1-5-domain-500)
    - First account created with Windows installation
    - Full control over system resources
    - Cannot be deleted but can be disabled/renamed
    - Disabled by default in Windows 10/Server 2016
  - **Guest**
    - Disabled by default
    - For temporary access with limited rights
    - Blank password by default (security risk)
  - **SYSTEM** (NT AUTHORITY\SYSTEM)
    - Used by OS for internal functions
    - No user profile but highest permission level
    - Cannot be added to groups
    - Full control over all files by default
  - **Network Service**
    - Used by Service Control Manager for services
    - Presents credentials to remote services
  - **Local Service**
    - Used by SCM with minimal privileges
    - Presents anonymous credentials to network

### Domain User Accounts
- Granted rights from domain to access shared resources
- Can log into any host in the domain
- Types include standard users, admin accounts, service accounts
- KRBTGT account: service account for Key Distribution, often targeted for attacks like Golden Ticket

### User Naming Attributes
- **UserPrincipalName (UPN)**: Primary logon name, typically email format
- **ObjectGUID**: Unique identifier that never changes, even if user is removed
- **SAMAccountName**: Legacy logon name supporting previous Windows versions
- **objectSID**: Security Identifier used during security interactions
- **sIDHistory**: Contains previous SIDs if user moved from another domain

### Common User Attributes Example
```
DistinguishedName : CN=username,CN=Users,DC=DOMAIN,DC=LOCAL
Enabled : True
GivenName : firstname
Name : username
ObjectClass : user
ObjectGUID : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName : username
SID : S-1-5-21-3842939050-3880317879-2865463114-1111
Surname : lastname
UserPrincipalName : username@DOMAIN.LOCAL
```

### Domain-joined vs. Non-Domain-joined Machines
- **Domain-joined**:
  - Centrally managed through domain controller
  - Configured via Group Policy
  - Easier information sharing within enterprise
  - Users can log in from any domain-joined machine
  - Common in enterprise environments

- **Non-domain joined (Workgroup)**:
  - Not managed by domain policy
  - Resource sharing more complicated outside local network
  - User accounts exist only on that specific machine
  - Users manage their own changes
  - Suitable for home or small business use

- Machine account (SYSTEM) in AD has similar rights to standard domain user
- SYSTEM access allows enumeration of domain data

## Active Directory Groups

### Groups vs. Organizational Units (OUs)
- **OUs**: For grouping objects to ease management and deploy Group Policy
- **Groups**: Primarily for assigning permissions to access resources

### Group Types
- **Security Groups**: For assigning permissions and rights to collections of users
- **Distribution Groups**: For email distribution lists, cannot assign permissions

### Group Scopes
- **Domain Local Groups**:
  - Only manage resources in domain where created
  - Cannot be used in other domains
  - Can contain users from other domains
  - Can nest into other local groups but not global groups

- **Global Groups**:
  - Can grant access to resources in another domain
  - Can only contain accounts from their own domain
  - Can be added to other global groups and local groups

- **Universal Groups**:
  - Can manage resources across multiple domains in forest
  - Available to all domains in organization
  - Can contain users from any domain
  - Stored in Global Catalog (changes trigger forest-wide replication)
  - Best practice: Add global groups as members rather than individual users

### Group Scope Examples
```
Administrators - DomainLocal
Domain Controllers - Global
Schema Admins - Universal
Enterprise Admins - Universal
Domain Admins - Global
Domain Users - Global
```

### Group Scope Conversion Rules
- Global → Universal: Only if not part of another Global Group
- Domain Local → Universal: Only if doesn't contain other Domain Local Groups
- Universal → Domain Local: No restrictions
- Universal → Global: Only if doesn't contain other Universal Groups

### Built-in vs. Custom Groups
- Built-in security groups created with Domain Local scope
- Only user accounts can be added to built-in groups (no nesting)
- Organizations typically create additional groups for specific purposes
- Software like Microsoft Exchange adds its own security groups

### Nested Group Membership
- Groups can be members of other groups
- Users inherit permissions from all groups they belong to (directly or indirectly)
- Can lead to unintended privileges that are difficult to detect
- Tools like BloodHound help uncover nested group memberships and privileges

### Important Group Attributes
- **cn**: Common-Name of the group
- **member**: List of user, group, and contact objects in the group
- **groupType**: Integer specifying the group type and scope
- **memberOf**: Groups that contain this group (nested group membership)
- **objectSid**: Security identifier of the group

<artifact type="text/markdown" id="active-directory-security-notes" title="Comprehensive Active Directory Security & Management Notes">
# Comprehensive Active Directory Security & Management Notes

## Rights and Privileges in Active Directory

### Fundamental Concepts
- **Rights**: Permissions to access objects (files, resources, etc.)
- **Privileges**: Permissions to perform actions (run programs, shutdown systems, reset passwords)
- Important to understand distinction: rights control object access while privileges control action permissions

### User Rights Assignment
User rights can be assigned through Group Policy or directly to users/groups. Critical privileges that can lead to privilege escalation include:

| Privilege | Description | Security Risk |
|-----------|-------------|--------------|
| SeRemoteInteractiveLogonRight | Allows RDP access | Remote access to sensitive systems |
| SeBackupPrivilege | Create system backups, access any file | Can extract SAM/SYSTEM hashes and NTDS.dit |
| SeDebugPrivilege | Debug processes, read memory | Can extract credentials from LSASS memory |
| SeImpersonatePrivilege | Impersonate tokens of privileged accounts | Can elevate to SYSTEM privileges |
| SeLoadDriverPrivilege | Load/unload device drivers | Potential for kernel-mode attacks |
| SeTakeOwnershipPrivilege | Take ownership of objects | Can gain access to restricted resources |

### Viewing User Privileges
- Command: `whoami /priv` shows all user rights assigned to current user
- Standard domain users have minimal privileges (typically just SeChangeNotifyPrivilege)
- Admin users have limited rights in non-elevated consoles due to UAC
- Elevated consoles (Run as Administrator) show full privileges available to admin users

### Critical Built-in AD Groups

| Group | Description | Security Implications |
|-------|-------------|----------------------|
| Account Operators | Create/modify most account types; can log in locally to DCs | Can create backdoor accounts; should have no members by default |
| Administrators | Full unrestricted access to computer/domain | Complete control; membership should be strictly limited |
| Backup Operators | Can back up files regardless of permissions; log on to DCs | Should be considered equivalent to Domain Admins; can extract credential data |
| DnsAdmins | Access to DNS information | Can potentially load malicious DLLs on DCs |
| Domain Admins | Full domain administrative access; local admin on all domain-joined machines | Complete domain control; membership should be minimal |
| Domain Users | Contains all user accounts in domain | Default group for all users |
| Enterprise Admins | Forest-wide administrative privileges | Can make forest-wide changes; exists only in root domain |
| Group Policy Creator Owners | Create/edit/delete GPOs | Can modify security settings across domain |
| Protected Users | Additional protections against credential theft | Members get enhanced security against certain attacks |
| Schema Admins | Can modify AD schema | Can potentially disrupt AD structure; exists only in root domain |
| Server Operators | Can modify services, access SMB shares on DCs | Can modify critical services on DCs |

## Active Directory Security Best Practices

### Account & Access Management
- **Account Separation**: Administrators must maintain separate accounts
  - Regular account for daily tasks (email, documents)
  - Administrative account only for admin tasks
  - Different strong passwords for each account

- **Password Security**:
  - Implement strong password complexity (12+ characters)
  - Use passphrases rather than simple passwords
  - Avoid common patterns (Welcome1, Season+Year, etc.)
  - Implement custom password filters to block common/weak passwords
  - Deploy multi-factor authentication (MFA) for remote access

- **LAPS (Local Administrator Password Solution)**:
  - Randomizes and rotates local administrator passwords
  - Prevents lateral movement via local admin account
  - Configure password rotation intervals (12/24 hours)
  - Store passwords securely in AD

- **Privileged Account Management**:
  - Limit Domain Admin account usage strictly to Domain Controllers
  - Never use Domain Admin accounts on workstations, jump hosts, or servers
  - Implement time-based access for privileged accounts when possible
  - Use dedicated Privileged Access Workstations (PAWs) for admin tasks

- **Group Managed Service Accounts (gMSA)**:
  - Managed by domain with 120-character passwords
  - Automatic password rotation
  - No user knows the password
  - Use for non-interactive services and applications

### Audit & Monitoring
- **Implement robust logging**:
  - Security event auditing
  - Authentication successes/failures
  - Privilege use and modification
  - Object access and modification
  - Policy changes

- **Regular AD auditing**:
  - Remove or disable unused accounts
  - Audit privileged group membership quarterly
  - Review service accounts and their permissions
  - Identify and remediate stale objects

- **Permission auditing**:
  - Review who has local admin rights
  - Audit Domain Admin and Enterprise Admin membership
  - Check file share permissions
  - Verify delegated rights in AD

### Infrastructure Hardening
- **Update Management**:
  - Implement WSUS (Windows Server Update Service) or SCCM
  - Establish regular patching schedules
  - Prioritize security patches for critical systems
  - Verify patch compliance

- **Server Role Limitation**:
  - Never install unnecessary roles on Domain Controllers
  - Avoid hosting IIS or web applications on DCs
  - Separate roles across different servers (web, database, etc.)
  - Follow principle of least functionality

- **Access Restriction**:
  - Limit local admin rights to only necessary users
  - Restrict RDP access to minimize attack surface
  - Implement jump servers for administrative access
  - Use Restricted Groups to control admin group membership

## Group Policy Management

### GPO Fundamentals
- **Group Policy Object (GPO)**: Virtual collection of policy settings for users/computers
- Each GPO has a unique name and GUID
- Can be linked to OUs, domains, or sites
- Single GPO can be linked to multiple containers
- Multiple GPOs can be applied to a single container

### GPO Order of Precedence (Processing Order)
1. **Local Group Policy**: Applied directly to host (lowest precedence)
2. **Site Policy**: Settings specific to enterprise sites
3. **Domain-wide Policy**: Settings applied across the domain
4. **Organizational Unit Policy**: Settings for specific OUs
5. **Nested OU Policies**: Settings for objects within nested OUs (highest precedence)

Within the same level, multiple GPOs are processed by link order:
- Lower link order number = higher precedence (1 processes before 2)
- Computer policy settings override equivalent user policy settings

### GPO Advanced Controls
- **Enforced Option** (formerly "No Override"):
  - Forces GPO settings to apply regardless of lower-level settings
  - Prevents child OUs from overriding settings
  - Enforced Default Domain Policy has absolute precedence

- **Block Inheritance**:
  - Prevents higher-level policies from applying to an OU
  - "Enforced" option overrides "Block Inheritance"

### Refresh and Application
- Default refresh interval: 90 minutes (±30 minutes random offset)
- Domain Controllers: 5-minute default refresh
- Maximum wait for new GPO: 120 minutes
- Manual update: `gpupdate /force`
- Can customize refresh interval via Group Policy
  - Avoid setting too frequent to prevent network congestion

### Common GPO Security Applications
- **Account & Password Policies**:
  - Password complexity requirements
  - Account lockout thresholds
  - Kerberos policy settings

- **Endpoint Protection**:
  - USB/removable media restrictions
  - Software restriction policies
  - Application control policies
  - AppLocker configurations

- **System Security**:
  - Screen lock enforcement
  - Security event audit policies
  - User rights assignments
  - Network access/security controls

- **Access Control**:
  - Command-line tool restrictions (PowerShell, CMD)
  - Login banner implementation
  - Service restrictions
  - Administrative template settings

### GPO Security Considerations
- GPOs can be attack vectors if permissions are misconfigured
- Attacker with GPO modification rights can:
  - Add rights to compromised accounts
  - Create local admin accounts
  - Establish scheduled tasks for malicious commands
  - Deploy backdoors throughout domain

- Important security practices:
  - Review GPO modification permissions regularly
  - Monitor GPO changes with robust auditing
  - Use delegated permissions sparingly
  - Implement approval processes for GPO changes
  - Regularly test GPO deployment in isolated environments

## Security in Active Directory: CIA Triad Balance

### Default AD Security Posture
- Active Directory leans toward **Availability** and **Confidentiality** by default
- Default installation lacks many hardening measures
- Requires additional configuration to achieve proper security balance

### Defense-in-Depth Approach
- No single security control is sufficient
- Combine multiple layers of protection:
  - Accurate asset inventory
  - Vulnerability patching
  - Configuration management
  - Endpoint protection
  - Security awareness training
  - Network segmentation
  - GPO-based controls

### Critical AD Security Tools & Features
- **Advanced Audit Policy Configuration**:
  - File access/modification tracking
  - Account logon/logoff monitoring
  - Policy change detection
  - Privilege usage tracking

- **Software Restriction Policies**:
  - Control what software can run on hosts
  - Application whitelisting capabilities
  - Script execution controls

- **Restricted Groups**:
  - Control group membership via Group Policy
  - Manage local administrator groups across domain
  - Control membership in privileged groups

- **Security Groups**:
  - Assign granular permissions to resources
  - Manage rights assignments collectively
  - Separate administrative functions
</artifact>


