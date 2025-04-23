---
title: "Footprinting"
description: "Footprinting is the initial phase of a penetration test, focused on passively gathering information about a target to map its digital presence"
pubDate: "Apr 20 2025"
heroImage: "/footprinting.jpg"
---

# 👣 Introduction 

Footprinting is the initial phase of a penetration test, focused on passively gathering information about a target to map its digital presence. It involves collecting data on domains, subdomains, IP ranges, services, and infrastructure without directly interacting with the target to avoid detection. This process lays the foundation for subsequent enumeration and exploitation by identifying potential entry points and vulnerabilities.

## 1. Enumeration Methodology Overview

Penetration testing, particularly enumeration, is a dynamic process requiring a structured yet adaptable approach. The provided methodology organizes enumeration into **six layers**, metaphorically represented as walls with gaps (vulnerabilities) to identify and exploit. These layers are divided into three levels:

- **Infrastructure-based Enumeration**: Focuses on external network presence and gateways.
- **Host-based Enumeration**: Examines services and processes on individual hosts.
- **OS-based Enumeration**: Analyzes operating system configurations and privileges.

### Key Principles
- **Systematic Approach**: The methodology is not a rigid step-by-step guide but a framework of systematic procedures to explore targets comprehensively.
- **Dynamic Adaptation**: Tools and techniques vary, but the goal remains consistent—identify vulnerabilities efficiently.
- **Time Constraints**: Penetration tests are time-bound, requiring prioritization of high-impact gaps. Even extensive tests may miss vulnerabilities, as seen in cases like the SolarWinds attack.
- **Layered Progression**: Each layer builds on the previous one, narrowing the focus from broad infrastructure to specific system details.

---

## 2. Six-Layer Enumeration Methodology

### Layer 1: Internet Presence
**Objective**: Identify the target’s online footprint to establish a starting point for enumeration.

- **Description**:
  - Focuses on discovering domains, subdomains, IP ranges, and other publicly accessible assets.
  - Critical in black-box tests where the scope allows exploration beyond predefined targets.
  - Primarily passive to avoid detection, using OSINT and third-party services.

- **Information Categories**:
  - **Domains and Subdomains**: Identify all domains (e.g., inlanefreight.com) and subdomains (e.g., matomo.inlanefreight.com).
  - **IP Ranges/Netblocks**: Map IP addresses associated with the company’s infrastructure.
  - **Certificates**: Analyze SSL certificates for additional subdomains.
  - **Third-Party Services**: Identify services like Google Workspace, Atlassian, or AWS.
  - **Security Measures**: Note DNS security features (e.g., SPF, DKIM, DMARC).

- **Techniques**:
  - **Certificate Transparency Logs**: Use tools like `crt.sh` to find subdomains in SSL certificates.
    ```bash
    curl -s https://crt.sh/?q=inlanefreight.com&output=json | jq .
    ```
    - Example Output: Subdomains like `matomo.inlanefreight.com`, `smartfactory.inlanefreight.com`.
  - **DNS Enumeration**: Query DNS records (A, MX, NS, TXT, SOA) to uncover infrastructure details.
    ```bash
    dig any inlanefreight.com
    ```
    - Example Output: A records (10.129.27.33), MX records (Google mail servers), TXT records (SPF, verification keys).
  - **OSINT**: Analyze the company’s website, job postings, and social media to infer technologies and structure.
  - **Shodan**: Identify internet-facing hosts and open ports.
    ```bash
    for i in $(cat ip-addresses.txt); do shodan host $i; done
    ```
    - Example Output: IP 10.129.127.22 with ports 25/tcp, 53/tcp, 80/tcp (Apache), 443/tcp.

- **Key Insights**:
  - Certificates often reveal active subdomains (e.g., `support.inlanefreight.htb`).
  - TXT records indicate third-party services (e.g., Atlassian, LogMeIn, Mailgun).
  - Shodan provides port and service details, such as OpenSSH 7.6p1 on 22/tcp.

- **Considerations**:
  - Avoid active scans to remain stealthy.
  - Verify third-party hosts (e.g., AWS) are in scope before testing.
  - Cross-reference findings with job postings to infer internal technologies (e.g., Atlassian Suite).

---

### Layer 2: Gateway
**Objective**: Understand the network interface, protection mechanisms, and topology of reachable targets.

- **Description**:
  - Analyzes firewalls, load balancers, and network configurations to identify entry points.
  - Less applicable to internal networks like Active Directory (covered in other modules).

- **Information Categories**:
  - **Network Protections**: Firewalls, IDS/IPS, WAFs.
  - **Network Topology**: Location of servers (DMZ, internal, cloud).
  - **Access Controls**: IP whitelisting, port filtering.

- **Techniques**:
  - **Firewall Detection**: Use Nmap’s ACK scan (`-sA`) to identify filtered ports.
    ```bash
    sudo nmap 10.129.127.22 -p 21,22,25 -sA -Pn
    ```
    - Example Output: 22/tcp unfiltered, 21/tcp filtered.
  - **Traceroute**: Map network hops to understand topology.
    ```bash
    sudo nmap 10.129.127.22 --traceroute
    ```
  - **Packet Analysis**: Use `tcpdump` to inspect responses for firewall behavior.
    ```bash
    sudo tcpdump -i eth0 host 10.129.127.22
    ```

- **Key Insights**:
  - Filtered ports indicate firewall presence.
  - Traceroute reveals network depth (e.g., single hop suggests DMZ).
  - Third-party services (e.g., Cloudflare) may protect gateways.

- **Considerations**:
  - Use stealthy scans (e.g., `-T2`, decoys) to avoid IDS/IPS detection.
  - Spoof trusted IPs or ports to bypass restrictions.

---

### Layer 3: Accessible Services
**Objective**: Enumerate services running on target hosts to understand their purpose and vulnerabilities.

- **Description**:
  - Examines open ports and services to identify their functionality and potential exploits.
  - Requires understanding service protocols to interact effectively.

- **Information Categories**:
  - **Service Types**: Web servers (Apache, Nginx), mail servers (Postfix), databases (MySQL).
  - **Versions**: Specific software versions (e.g., Apache 2.4.29).
  - **Configurations**: Exposed directories, default settings.

- **Techniques**:
  - **Service Scanning**: Use Nmap’s version detection (`-sV`).
    ```bash
    sudo nmap 10.129.127.22 -p- -sV -v
    ```
    - Example Output: 22/tcp (OpenSSH 7.6p1), 25/tcp (Postfix), 80/tcp (Apache 2.4.29).
  - **Banner Grabbing**: Manually connect to services with `nc` or `telnet`.
    ```bash
    nc -nv 10.129.127.22 25
    ```
    - Example Output: `220 inlane ESMTP Postfix (Ubuntu)`.
  - **NSE Scripts**: Run vulnerability scans or service-specific scripts.
    ```bash
    sudo nmap 10.129.127.22 -p 80 --script vuln
    ```
    - Example Output: Apache 2.4.29 with CVEs (e.g., CVE-2019-0211).

- **Key Insights**:
  - Service versions reveal known vulnerabilities (e.g., Apache 2.4.29 CVEs).
  - Banners may disclose OS details (e.g., Ubuntu).
  - NSE scripts identify misconfigurations (e.g., WordPress admin folder).

- **Considerations**:
  - Cross-reference service versions with vulnerability databases (e.g., CVE Details).
  - Test for default credentials or exposed admin panels.
  - Be cautious with intrusive scripts to avoid service disruption.

---

### Layer 4: Processes
**Objective**: Identify running processes and their interactions to uncover exploitable tasks.

- **Description**:
  - Focuses on processes initiated by services, including user inputs and system-generated tasks.
  - Examines process sources, targets, and dependencies.

- **Information Categories**:
  - **Process Names**: Background tasks (e.g., cron jobs, daemons).
  - **Inputs/Outputs**: Data flows between processes.
  - **Dependencies**: Linked services or libraries.

- **Techniques**:
  - **Process Enumeration**: If access is gained, use `ps` or `top` to list processes.
    ```bash
    ps aux | grep apache
    ```
  - **Log Analysis**: Check service logs for process details.
    ```bash
    cat /var/log/apache2/access.log
    ```
  - **Network Activity**: Monitor process network connections.
    ```bash
    netstat -tulnp
    ```

- **Key Insights**:
  - Misconfigured processes may expose sensitive data (e.g., log files).
  - Background tasks (e.g., cron jobs) may run with elevated privileges.
  - Dependencies may have known vulnerabilities.

- **Considerations**:
  - Requires initial access to enumerate processes.
  - Focus on processes linked to accessible services (e.g., web server tasks).
  - Avoid disrupting critical processes during testing.

---

### Layer 5: Privileges
**Objective**: Analyze user and group privileges to identify escalation opportunities.

- **Description**:
  - Examines permissions assigned to services and users.
  - Common in environments like Active Directory where privilege misconfigurations are prevalent.

- **Information Categories**:
  - **Service Accounts**: Users running services (e.g., Apache’s `www-data`).
  - **Group Permissions**: Access to sensitive files or directories.
  - **Sudo Rights**: Commands executable with elevated privileges.

- **Techniques**:
  - **User Enumeration**: List users and groups.
    ```bash
    cat /etc/passwd
    ```
  - **Privilege Checks**: Identify sudo permissions.
    ```bash
    sudo -l
    ```
  - **File Permissions**: Check for misconfigured files.
    ```bash
    find / -perm -4000 2>/dev/null
    ```

- **Key Insights**:
  - Service accounts with excessive permissions are common in Active Directory.
  - Sudo misconfigurations allow privilege escalation.
  - World-writable files may expose sensitive data.

- **Considerations**:
  - Requires initial access to enumerate privileges.
  - Test privilege escalation vectors carefully to avoid system impact.
  - Document all findings for privilege escalation reports.

---

### Layer 6: OS Setup
**Objective**: Collect details about the operating system and its configuration to assess internal security.

- **Description**:
  - Analyzes OS version, patches, and security settings.
  - Reflects the administrative team’s security practices.

- **Information Categories**:
  - **OS Version**: Specific OS and kernel (e.g., Ubuntu 18.04, Linux 4.15).
  - **Patches**: Applied security updates.
  - **Security Settings**: Firewall rules, SELinux/AppArmor.

- **Techniques**:
  - **OS Detection**: Use Nmap’s OS fingerprinting.
    ```bash
    sudo nmap 10.129.127.22 -O
    ```
    - Example Output: Linux 2.6.32–4.9.
  - **System Info**: If access is gained, check OS details.
    ```bash
    lsb_release -a
    ```
  - **Patch Level**: List installed packages.
    ```bash
    dpkg -l
    ```

- **Key Insights**:
  - Outdated OS versions are vulnerable to known exploits.
  - Missing patches indicate poor maintenance.
  - Security settings (e.g., disabled firewalls) expose systems.

- **Considerations**:
  - OS enumeration often requires internal access.
  - Cross-reference OS versions with exploit databases.
  - Document findings to assess administrative competence.

---

## 3. Additional Enumeration Techniques

### Cloud Resources
**Objective**: Identify and assess cloud-based assets for misconfigurations.

- **Description**:
  - Focuses on cloud storage (e.g., AWS S3, Azure Blobs, GCP Cloud Storage).
  - Misconfigured buckets often expose sensitive data.

- **Techniques**:
  - **DNS Lookup**: Identify cloud-hosted subdomains.
    ```bash
    for i in $(cat subdomainlist); do host $i | grep "has address" | grep inlanefreight; done
    ```
    - Example Output: `s3-website-us-west-2.amazonaws.com 10.129.95.250`.
  - **Google Dorks**: Search for exposed cloud resources.
    ```plaintext
    site:*.amazonaws.com inlanefreight
    ```
  - **GrayHatWarfare**: Discover public buckets and files.
    - Example: Search for PDFs, SSH keys in AWS S3 buckets.
  - **Source Code Analysis**: Inspect website source for cloud storage links.
    ```html
    <link rel="preconnect" href="https://s3.amazonaws.com/...">
    ```

- **Key Insights**:
  - Public S3 buckets may contain sensitive files (e.g., SSH keys, PDFs).
  - Cloud storage in DNS records suggests administrative use.
  - Source code often reveals cloud integration.

- **Considerations**:
  - Verify scope before testing cloud resources.
  - Use passive methods (e.g., GrayHatWarfare) to avoid detection.
  - Test for unauthenticated access to buckets.

---

### Staff Reconnaissance
**Objective**: Gather information about employees to infer technologies and security measures.

- **Description**:
  - Analyzes employee profiles and job postings to understand infrastructure and skillsets.
  - Focuses on technical staff (developers, security engineers).

- **Techniques**:
  - **LinkedIn Search**: Identify employees and their skills.
    - Example: Job posting requiring Flask, Django, Atlassian Suite.
  - **GitHub Analysis**: Review public repositories for project details.
    ```plaintext
    https://github.com/employee/opensource-project
    ```
  - **Security Research**: Search for Django/Flask misconfigurations.
    - Example: GitHub repository on OWASP Top 10 for Django.

- **Key Insights**:
  - Job postings reveal technologies (e.g., PostgreSQL, REST APIs).
  - Employee profiles indicate frameworks (e.g., React, Svelte).
  - Public repositories may expose configurations or vulnerabilities.

- **Considerations**:
  - Focus on technical roles for infrastructure insights.
  - Avoid direct interaction with employees to maintain stealth.
  - Cross-reference findings with service enumeration.

---

## 4. Practical Example: Inlanefreight Case Study

### Scenario
- **Test Type**: Black-box external penetration test.
- **Target**: Inlanefreight infrastructure (e.g., inlanefreight.com).
- **Scope**: All company-hosted assets, excluding third-party providers.

### Layer 1: Internet Presence
- **Findings**:
  - Subdomains: `blog.inlanefreight.com` (10.129.24.93), `matomo.inlanefreight.com` (10.129.127.22).
  - DNS Records: A (10.129.27.33), MX (Google), TXT (Atlassian, LogMeIn, Mailgun).
  - Certificate: Includes `support.inlanefreight.htb`, `www.inlanefreight.htb`.
  - Shodan: 10.129.127.22 has ports 25/tcp, 80/tcp (Apache), 443/tcp.

- **Actions**:
  - Used `crt.sh` and `dig` to map subdomains and services.
  - Noted third-party services (e.g., Google Gmail, Atlassian) for potential misconfigurations.

### Layer 2: Gateway
- **Findings**:
  - Port 22/tcp unfiltered, 21/tcp filtered (firewall presence).
  - Single-hop traceroute suggests DMZ-hosted servers.

- **Actions**:
  - Ran Nmap ACK scan (`-sA`) to detect firewall rules.
  - Used `tcpdump` to analyze packet responses.

### Layer 3: Accessible Services
- **Findings**:
  - 80/tcp: Apache 2.4.29 with WordPress 5.3.4, vulnerable to CVE-2019-0211.
  - 25/tcp: Postfix, supports STARTTLS, VRFY commands.
  - 22/tcp: OpenSSH 7.6p1 (Ubuntu).

- **Actions**:
  - Performed Nmap version scan (`-sV`) and NSE vuln scan.
  - Grabbed banners with `nc` to confirm Ubuntu OS.

### Layer 4: Processes
- **Findings**:
  - Apache processes running as `www-data`.
  - Potential cron jobs for WordPress updates.

- **Actions**:
  - Hypothetical access assumed; would check `ps aux` and logs.

### Layer 5: Privileges
- **Findings**:
  - `www-data` user likely has limited permissions.
  - Potential misconfigured sudo rights for web services.

- **Actions**:
  - Would enumerate users and permissions if access gained.

### Layer 6: OS Setup
- **Findings**:
  - OS: Linux 2.6.32–4.9 (likely Ubuntu 18.04).
  - No patch details available without access.

- **Actions**:
  - Used Nmap OS detection (`-O`) to estimate OS.

### Cloud Resources
- **Findings**:
  - S3 bucket: `s3-website-us-west-2.amazonaws.com` (10.129.95.250).
  - Potential public files (e.g., PDFs) in bucket.

- **Actions**:
  - Searched Google Dorks and GrayHatWarfare for bucket contents.
  - Inspected website source for S3 links.

### Staff Reconnaissance
- **Findings**:
  - Job posting: Requires Flask, Django, Atlassian Suite.
  - Employee profile: Uses React, Svelte; contributes to Django projects.

- **Actions**:
  - Searched LinkedIn for technical staff.
  - Reviewed GitHub for Django security insights.

---

## 5. Key Considerations
- **Stealth**: Use passive techniques (e.g., OSINT, `crt.sh`) in early layers to avoid detection.
- **Scope Compliance**: Exclude third-party providers (e.g., AWS, Google) unless explicitly allowed.
- **Tool Diversity**: Combine tools (Nmap, Shodan, GrayHatWarfare) for comprehensive coverage.
- **Documentation**: Record all findings, including commands and outputs, for reporting.
- **Time Management**: Prioritize high-impact layers (Internet Presence, Accessible Services) in time-constrained tests.

---

## 6. Resources
- **Nmap NSE Documentation**: [https://nmap.org/nsedoc/](https://nmap.org/nsedoc/)
- **Certificate Transparency**: [https://crt.sh/](https://crt.sh/)
- **Shodan**: [https://www.shodan.io/](https://www.shodan.io/)
- **GrayHatWarfare**: [https://grayhatwarfare.com/](https://grayhatwarfare.com/)
- **OWASP Django Security**: GitHub repositories on Django best practices.


# FTP and TFTP Notes

## File Transfer Protocol (FTP)
- **Overview**: One of the oldest Internet protocols, operates in the application layer of TCP/IP stack, similar to HTTP or POP.
- **Operation**:
  - Uses two channels:
    - **Control Channel**: Established via TCP port 21 for sending commands and receiving status codes.
    - **Data Channel**: Uses TCP port 20 for data transmission, supports error checking and resumable transfers.
  - **Modes**:
    - **Active**: Client opens port 21, informs server of response port; may be blocked by client firewalls.
    - **Passive**: Server provides a port for the client to initiate the data channel, bypassing firewall issues.
- **Commands**: Includes upload/download files, manage directories, delete files; server responds with status codes.
- **Authentication**:
  - Typically requires credentials.
  - **Anonymous FTP**: Allows access without passwords, but poses security risks; often limited in functionality.
- **Security Concerns**: Susceptible to sniffing if unencrypted; anonymous access increases vulnerability.

## Trivial File Transfer Protocol (TFTP)
- **Overview**: Simpler than FTP, lacks user authentication, uses UDP (unreliable) instead of TCP.
- **Operation**:
  - No authentication; access based on file read/write permissions in the OS.
  - Operates in shared directories with global read/write access.
- **Use Case**: Limited to local, protected networks due to minimal security.
- **Commands**:
  - `connect`: Sets remote host/port.
  - `get`: Downloads file(s) from remote to local host.
  - `put`: Uploads file(s) from local to remote host.
  - `quit`: Exits TFTP.
  - `status`: Displays transfer mode, connection status, timeout, etc.
  - `verbose`: Toggles detailed transfer information.
  - No directory listing functionality.

## vsFTPd (Very Secure FTP Daemon)
- **Overview**: Popular FTP server on Linux, configurable via `/etc/vsftpd.conf`.
- **Installation**: `sudo apt install vsftpd`.
- **Key Configuration Options**:
  - `listen_ipv6=YES`: Enables IPv6 listening.
  - `anonymous_enable=NO`: Disables anonymous access.
  - `local_enable=YES`: Allows local user logins.
  - `dirmessage_enable=YES`: Shows directory messages.
  - `xferlog_enable=YES`: Logs transfers.
  - `connect_from_port_20=YES`: Uses port 20 for data.
  - `anon_root=/home/ftpuser`: Sets directory for anonymous users.
  - `ssl_enable=YES`: Enables SSL encryption.
- **Security**:
  - `/etc/ftpusers`: Lists users denied FTP access (e.g., guest, john).
  - **Dangerous Settings**:
    - `anonymous_enable=YES`: Allows anonymous logins.
    - `anon_upload_enable=YES`: Permits anonymous uploads.
    - `anon_mkdir_write_enable=YES`: Allows anonymous directory creation.
    - `no_anon_password=YES`: Skips password for anonymous.
    - `write_enable=YES`: Enables write permissions.
  - Misconfigurations can lead to unauthorized access or privilege escalation.

## Practical FTP Usage
- **Connecting**:
  - Anonymous login: `ftp> anonymous` (if enabled).
  - Check status: `ftp> status` (shows mode, connection details).
  - Enable debugging: `ftp> debug` or `ftp> trace` for detailed output.
- **Listing Files**:
  - `ftp> ls`: Lists directory contents.
  - `ftp> ls -R`: Recursive listing for directory structure.
- **File Transfers**:
  - Download: `ftp> get filename` (e.g., `get Important Notes.txt`).
  - Upload: `ftp> put filename` (e.g., `put testupload.txt`).
  - Bulk download: `wget -m --no-passive ftp://anonymous@server`.
- **Directory Structure**: Files downloaded via `wget` are stored in a folder named after the server’s address.

## Security and Enumeration
- **Risks**:
  - Anonymous access can expose sensitive files.
  - File uploads to web-linked FTP servers may enable remote code execution (RCE).
  - Unencrypted FTP exposes data to interception.
- **Footprinting with Nmap**:
  - Scan: `sudo nmap -sV -p21 -sC -A server`.
  - Scripts:
    - `ftp-anon.nse`: Checks for anonymous access and lists directory.
    - `ftp-syst.nse`: Displays server status (e.g., version, configuration).
    - Others: Check for vulnerabilities (e.g., `ftp-vsftpd-backdoor.nse`).
  - Update scripts: `sudo nmap --script-updatedb`.
  - Trace: `nmap -sV -p21 -sC -A --script-trace` for detailed command/port info.
- **SSL/TLS FTP**:
  - Use `openssl s_client -connect server:21 -starttls ftp` to interact and view SSL certificates.
  - Certificates may reveal organizational details (e.g., location, email).

## Mitigation
- Disable anonymous access unless necessary.
- Use `/etc/ftpusers` to restrict user access.
- Enable SSL/TLS for encrypted connections.
- Implement fail2ban to block brute-force attempts.
- Regularly audit configurations and permissions.
- Harden internal systems to prevent misconfiguration exploits.

---

## Overview of SMB
- **Definition**: SMB (Server Message Block) is a client-server protocol for accessing files, directories, printers, and other network resources. It facilitates inter-process communication across networked systems.
- **Primary Use**: Predominantly used in Windows environments, with backward compatibility for older Microsoft systems. Samba extends SMB support to Linux/Unix for cross-platform communication.
- **Operation**:
  - SMB operates over TCP, using a three-way handshake to establish connections.
  - Ports:
    - **CIFS/SMB 1**: Uses NetBIOS over TCP ports 137, 138, 139, and TCP 445.
    - **SMB 2/3**: Primarily uses TCP 445.
  - Shares: Servers expose parts of their file systems as shares, with access controlled via Access Control Lists (ACLs) independent of local file system permissions.

### SMB Versions and Features
| **Version**   | **Supported Systems**               | **Key Features**                                      |
|---------------|-------------------------------------|------------------------------------------------------|
| **CIFS**      | Windows NT 4.0                     | NetBIOS-based communication                          |
| **SMB 1.0**   | Windows 2000                       | Direct TCP connection                                |
| **SMB 2.0**   | Windows Vista, Server 2008         | Performance upgrades, message signing, caching       |
| **SMB 2.1**   | Windows 7, Server 2008 R2          | Locking mechanisms                                   |
| **SMB 3.0**   | Windows 8, Server 2012             | Multichannel, end-to-end encryption, remote storage  |
| **SMB 3.0.2** | Windows 8.1, Server 2012 R2        | Incremental improvements                             |
| **SMB 3.1.1** | Windows 10, Server 2016            | Integrity checking, AES-128 encryption               |

**Note**: SMB 1 (CIFS) is outdated and insecure, often disabled in modern systems due to vulnerabilities like EternalBlue. SMB 2 and 3 are recommended for improved security and performance.

---

## Samba
- **Overview**: Samba is an open-source implementation of SMB/CIFS for Unix-based systems, enabling interoperability with Windows systems.
- **Key Features**:
  - Supports SMB versions, including CIFS, SMB 1, 2, and 3.
  - Integrates with Active Directory (AD) as a domain member (Samba 3) or domain controller (Samba 4).
  - Uses daemons:
    - **smbd**: Handles SMB file and print services.
    - **nmbd**: Manages NetBIOS name resolution and workgroup announcements.
- **Configuration File**: `/etc/samba/smb.conf`
  - **Global Section**: Defines server-wide settings (e.g., workgroup, logging, authentication).
  - **Share Sections**: Configures specific shares (e.g., path, permissions, guest access).

### Example Configuration
```ini
[global]
  workgroup = DEV.INFREIGHT.HTB
  server string = DEVSMB
  log file = /var/log/samba/log.%m
  max_log_size = 1000
  server role = standalone server
  map to guest = bad user
  usershare allow guests = yes

[notes]
  comment = CheckIT
  path = /mnt/notes/
  browseable = yes
  read only = no
  writable = yes
  guest ok = yes
  create mask = 0777
  directory mask = 0777
```

### Dangerous Settings
Certain configurations can expose systems to risks:
| **Setting**                 | **Description**                                      | **Risk**                                                                 |
|-----------------------------|----------------------------------------------|--------------------------------------------------------------------------|
| `browseable = yes`          | Lists shares publicly                        | Attackers can discover shares without authentication.                    |
| `read only = no` / `writable = yes` | Allows file modifications                    | Unauthorized users can alter or upload malicious files.                  |
| `guest ok = yes`            | Permits access without credentials           | Enables anonymous access, increasing exposure to attacks.                 |
| `create mask = 0777` / `directory mask = 0777` | Sets permissive file permissions | Newly created files are world-readable/writable, enabling exploitation.   |
| `map to guest = bad user`   | Maps invalid users to guest account          | Failed login attempts may still grant access as a guest.                 |

---

## Practical Usage
### Connecting to SMB Shares
- **List Shares Anonymously**:
  ```bash
  smbclient -N -L //10.129.14.128
  ```
  Output:
  ```
  Sharename   Type   Comment
  ---------   ----   -------
  print$      Disk   Printer Drivers
  home        Disk   INFREIGHT Samba
  dev         Disk   DEVenv
  notes       Disk   CheckIT
  IPC$        IPC    IPC Service (DEVSW)
  ```
- **Connect to a Share**:
  ```bash
  smbclient //10.129.14.128/notes
  ```
  - Use `-N` for anonymous login if `guest ok = yes`.
  - Commands within `smbclient`:
    - `ls`: List directory contents.
    - `get <file>`: Download a file (e.g., `get prep-prod.txt`).
    - `put <file>`: Upload a file.
    - `help`: List available commands.

### Managing Samba
- **Restart Service**:
  ```bash
  sudo systemctl restart smbd
  ```
- **Check Status**:
  ```bash
  smbstatus
  ```
  Displays connected users, shares, and encryption details.

---

## Security Risks
1. **Anonymous Access**:
   - Shares with `guest ok = yes` or `map to guest = bad user` allow unauthenticated access, exposing sensitive data.
   - Example: The `notes` share in the document allows anonymous users to read/write files, potentially leaking `prep-prod.txt`.

2. **Permissive Permissions**:
   - `create mask = 0777` and `directory mask = 0777` make files world-readable/writable, enabling attackers to upload malicious scripts.

3. **Weak Authentication**:
   - Poorly configured passwords or reliance on outdated SMB 1 can be brute-forced or exploited.

4. **Information Disclosure**:
   - Enumeration tools can reveal user accounts, share details, and system information, aiding further attacks.

5. **Remote Code Execution (RCE)**:
   - Misconfigured shares linked to web servers or executable directories may allow attackers to upload and execute malicious files.

---

## Enumeration Techniques
Enumeration is critical for identifying vulnerabilities in SMB/Samba setups. The document highlights several tools and methods:

### 1. Nmap
- **Basic Scan**:
  ```bash
  sudo nmap 10.129.14.128 -sV -sC -p139,445
  ```
  Output:
  ```
  PORT    STATE SERVICE      VERSION
  139/tcp open  netbios-ssn  Samba smbd 4.6.2
  445/tcp open  netbios-ssn  Samba smbd 4.6.2
  ```
  - Reveals Samba version and basic security settings (e.g., message signing).

- **NSE Scripts**:
  - `smb-enum-shares.nse`: Lists available shares.
  - `smb-enum-users.nse`: Enumerates user accounts.
  - `smb-security-mode.nse`: Checks security settings.

### 2. smbclient
- Lists shares and allows interaction with accessible shares anonymously.
  ```bash
  smbclient -N -L //10.129.14.128
  ```

### 3. rpcclient
- Performs MS-RPC queries to extract detailed information.
  ```bash
  rpcclient -U "" 10.129.14.128
  ```
  - Commands:
    - `srvinfo`: Server details (e.g., OS version, server type).
    - `enumdomains`: Lists domains.
    - `netshareenumall`: Enumerates all shares.
    - `enumdomusers`: Lists domain users.
    - `queryuser <RID>`: Retrieves user details by RID.
  - Example:
    ```bash
    rpcclient $> netshareenumall
    netname: notes
    remark: CheckIT
    path: C:\mnt\notes
    ```

### 4. Impacket (samrdump.py)
- Enumerates users and groups via RPC.
  ```bash
  samrdump.py 10.129.14.128
  ```
  Output:
  ```
  Found user: mrb3n, uid = 1000
  Found user: cry0l1t3, uid = 1001
  ```

### 5. smbmap
- Maps shares and permissions.
  ```bash
  smbmap -H 10.129.14.128
  ```
  Output:
  ```
  Disk         Permissions   Comment
  ----         -----------   -------
  notes        READ, WRITE   CheckIT
  ```

### 6. CrackMapExec
- Automates SMB enumeration and credential testing.
  ```bash
  crackmapexec smb 10.129.14.128 --shares -u '' -p ''
  ```
  Output:
  ```
  SMB  10.129.14.128  445  DEVSWB  [+] Enumerated shares
  notes  READ, WRITE  CheckIT
  ```

### 7. enum4linux-ng
- Comprehensive SMB enumeration tool.
  ```bash
  ./enum4linux-ng.py 10.129.14.128 -A
  ```
  Output:
  ```
  Shares:
    notes: CheckIT (Disk)
  Users:
    mrb3n (1000)
    cry0l1t3 (1001)
  ```

### Brute-Forcing RIDs
- Use `rpcclient` to enumerate users by guessing Relative Identifiers (RIDs):
  ```bash
  for i in $(seq 500 1100); do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x' $i)"; done
  ```

---

## Mitigation Strategies
To secure SMB/Samba servers and mitigate risks:
1. **Disable SMB 1**:
   - SMB 1 is vulnerable to exploits like EternalBlue. Disable it via server configuration or Windows Group Policy.

2. **Restrict Anonymous Access**:
   - Set `guest ok = no` and `map to guest = never` in `smb.conf`.
   - Use `/etc/samba/smbusers` to restrict specific users.

3. **Enforce Strong Authentication**:
   - Require complex passwords and enable `DOMAIN_PASSWORD_COMPLEX = true` in domain policies.
   - Use Kerberos or NTLMv2 for authentication.

4. **Enable Encryption**:
   - Configure SMB 3 with encryption (`smb encrypt = required` in `smb.conf`).
   - Use AES-128 (SMB 3.1.1) for secure data transfer.

5. **Limit Share Permissions**:
   - Set `read only = yes` and restrictive `create mask`/`directory mask` (e.g., `0700`).
   - Use ACLs to fine-tune access for users/groups.

6. **Firewall Rules**:
   - Block ports 137, 138, 139, and 445 externally.
   - Allow only trusted internal networks to access SMB.

7. **Monitor and Log**:
   - Enable logging (`log file = /var/log/samba/log.%m`) and monitor with tools like `smbstatus`.
   - Use intrusion detection systems (e.g., fail2ban) to block brute-force attempts.

8. **Regular Audits**:
   - Review `smb.conf` for dangerous settings.
   - Use tools like `testparm` to validate configurations.
   - Conduct periodic vulnerability scans with Nmap or Nessus.

9. **Patch Management**:
   - Keep Samba and Windows systems updated to address known vulnerabilities (e.g., CVE-2017-0144 for EternalBlue).

10. **Network Segmentation**:
    - Isolate SMB servers in separate VLANs to limit lateral movement by attackers.

---

## Practical Example: Exploiting the `notes` Share
The document’s `notes` share is highly insecure due to:
- `guest ok = yes`: Allows anonymous access.
- `writable = yes`: Permits file uploads.
- `create mask = 0777`: Makes uploaded files executable.

### Attack Scenario
1. **Enumerate Shares**:
   ```bash
   smbclient -N -L //10.129.14.128
   ```
   Identifies the `notes` share.

2. **Access Share**:
   ```bash
   smbclient //10.129.14.128/notes
   smb: \> ls
   prep-prod.txt
   smb: \> get prep-prod.txt
   ```
   Downloads `prep-prod.txt`, which contains references to `code-assessment.py`.

3. **Upload Malicious File**:
   ```bash
   smb: \> put malicious.sh
   ```
   Uploads a script that could be executed if the share is linked to a web server or cron job.

4. **Exploit**:
   - If `notes` is accessible via a web server, an attacker could upload a webshell and achieve RCE.
   - Alternatively, enumerate users (`mrb3n`, `cry0l1t3`) via `rpcclient` and attempt credential brute-forcing.

### Mitigation for `notes` Share
- Update `smb.conf`:
  ```ini
  [notes]
    comment = CheckIT
    path = /mnt/notes/
    browseable = no
    read only = yes
    guest ok = no
    create mask = 0644
    directory mask = 0755
  ```
- Restart Samba:
  ```bash
  sudo systemctl restart smbd
  ```
- Verify with `smbclient -N -L //10.129.14.128` to ensure `notes` is no longer anonymously accessible.

---

## Comparison with FTP/TFTP
Since the user referenced FTP and TFTP in a prior context, here’s a brief comparison with SMB:

| **Feature**           | **SMB**                              | **FTP**                              | **TFTP**                             |
|-----------------------|--------------------------------------|--------------------------------------|--------------------------------------|
| **Protocol**          | TCP (139, 445)                      | TCP (20, 21)                        | UDP (69)                            |
| **Authentication**    | Supports user credentials, guest access | Supports credentials, anonymous access | No authentication                  |
| **Encryption**        | SMB 3+ supports AES-128             | FTPS (SSL/TLS)                      | None                                |
| **Reliability**       | Reliable (TCP)                      | Reliable (TCP)                      | Unreliable (UDP)                   |
| **Use Case**          | File/printer sharing, AD integration | File transfers                      | Simple file transfers (e.g., boot images) |
| **Security**          | ACLs, encryption (SMB 3)            | Susceptible to sniffing if unencrypted | Minimal security, local networks only |
| **Enumeration**       | Tools: smbclient, rpcclient, Nmap   | Tools: Nmap, ftp-anon.nse           | Limited enumeration tools           |

**Key Difference**: SMB is more feature-rich and integrated with Windows/AD environments, while FTP/TFTP are simpler but less secure and lack advanced access controls.

---

# NFS Notes

## Network File System (NFS)
- **Overview**: NFS, developed by Sun Microsystems, enables access to remote file systems as if they were local, primarily used in Linux/Unix environments. Unlike SMB, it uses a distinct protocol and is not natively compatible with Windows SMB servers.
- **Purpose**: Facilitates file sharing across Unix-based systems, similar to SMB for Windows or FTP for general file transfers.
- **Operation**:
  - Based on Open Network Computing Remote Procedure Call (ONC RPC) over TCP/UDP port 111.
  - Uses External Data Representation (XDR) for platform-independent data exchange.
  - Ports: Primarily 111 (RPC) and 2049 (NFS service, especially NFSv4).
  - Authentication: Handled by RPC, typically via UNIX UID/GID mappings; no native NFS authentication mechanism.
  - Authorization: Derived from file system permissions, translated by the server into UNIX syntax.

### NFS Versions and Features
| **Version** | **Key Features** | **Notes** |
|-------------|------------------|-----------|
| **NFSv2** | Operated over UDP, basic functionality | Outdated, widely supported but limited security |
| **NFSv3** | Client-based authentication, UDP/TCP support | Long-standing, lacks user authentication |
| **NFSv4** | Kerberos integration, single port (2049), improved error reporting | Not backward-compatible with NFSv2 |
| **NFSv4.1** | Parallel NFS (pNFS) for clustered servers, session trunking (multipathing) | Simplifies firewall configuration with port 2049 |

**Note**: NFSv4+ is recommended for modern deployments due to enhanced security (Kerberos) and simplified port usage.

## Configuration
- **Configuration File**: `/etc/exports` defines NFS shares and access controls.
- **Structure**: Specifies directories, allowed hosts/subnets, and permissions/options.
- **Example**:
  ```
  /mnt/nfs 10.129.14.0/24(rw,sync,no_subtree_check)
  ```
  - Exports `/mnt/nfs` to the subnet `10.129.14.0/24` with read/write (`rw`), synchronous writes (`sync`), and no subtree checking (`no_subtree_check`).

### Common Options
| **Option** | **Description** | **Risk** |
|------------|-----------------|----------|
| `rw` | Read/write access | Allows modifications, risking unauthorized changes |
| `ro` | Read-only access | Safer, limits modifications |
| `sync` | Synchronous data writes | Slower but ensures data integrity |
| `async` | Asynchronous writes | Faster but risks data loss |
| `insecure` | Allows ports above 1024 | Enables non-root users to interact, increasing attack surface |
| `no_subtree_check` | Disables subdirectory permission checks | Simplifies access but may expose unintended files |
| `root_squash` | Maps root UID (0) to nobody | Prevents root access to files |
| `no_root_squash` | Allows root UID (0) full access | Dangerous, enables root-level modifications |

### Dangerous Settings
- **`insecure`**: Permits non-privileged ports (>1024), allowing non-root users to interact with NFS, increasing vulnerability to unauthorized access.
- **`no_root_squash`**: Grants root-level access to clients, enabling full control over the share (e.g., modifying/deleting critical files).
- **`rw` with broad access**: Exposing writable shares to entire subnets (e.g., `10.129.14.0/24`) risks unauthorized modifications.
- **Lack of authentication**: Reliance on UID/GID mappings without Kerberos (NFSv4) assumes trusted networks, which is risky in untrusted environments.

## Practical Usage
### Setting Up an NFS Share
1. **Edit Exports**:
   ```bash
   echo '/mnt/nfs 10.129.14.0/24(rw,sync,no_subtree_check)' >> /etc/exports
   ```
2. **Restart NFS Service**:
   ```bash
   systemctl restart nfs-kernel-server
   ```
3. **Verify Exports**:
   ```bash
   exportfs
   ```
   Output:
   ```
   /mnt/nfs 10.129.14.0/24
   ```

### Accessing NFS Shares
1. **List Available Shares**:
   ```bash
   showmount -e 10.129.14.128
   ```
   Output:
   ```
   Export list for 10.129.14.128:
   /mnt/nfs 10.129.14.0/24
   ```
2. **Mount Share**:
   ```bash
   mkdir target-NFS
   sudo mount -t nfs 10.129.14.128:/mnt/nfs target-NFS/ -o nolock
   ```
3. **Inspect Contents**:
   ```bash
   cd target-NFS
   ls -l
   ```
   Example Output:
   ```
   -rw-r--r-- 1 cry0l1t3 cry0l1t3 1872 Sep 25 00:55 cry0l1t3.priv
   -rw-r--r-- 1 cry0l1t3 cry0l1t3  348 Sep 25 00:55 cry0l1t3.pub
   -rw-r--r-- 1 root     root     1872 Sep 19 17:27 id_rsa
   -rw-r--r-- 1 root     root      348 Sep 19 17:28 id_rsa.pub
   ```
4. **Unmount Share**:
   ```bash
   cd ..
   sudo umount target-NFS
   ```

### Privilege Escalation via NFS
- **Scenario**: If `no_root_squash` is enabled, a client can create files as UID 0 (root).
- **Steps**:
  1. Mount the NFS share locally.
  2. Create a malicious executable (e.g., a SUID binary) with UID 0:
     ```bash
     echo '#!/bin/bash\n/bin/bash' > /mnt/nfs/malicious.sh
     chmod +s /mnt/nfs/malicious.sh
     ```
  3. On the server, execute `malicious.sh` to gain root privileges.
- **Mitigation**: Always enable `root_squash` unless absolutely necessary.

## Security Risks
1. **Weak Authentication**:
   - NFS relies on UID/GID mappings, which are not verified by the server. A malicious client can spoof UIDs to access files.
   - Example: A client with UID 1000 can access files owned by UID 1000 on the server, regardless of the actual user.

2. **No Root Squash**:
   - Allows clients to act as root, enabling full control over the share (e.g., modifying `/etc/passwd`).

3. **Broad Subnet Access**:
   - Exporting to entire subnets (e.g., `10.129.14.0/24`) increases exposure to unauthorized clients.

4. **Insecure Ports**:
   - The `insecure` option allows non-privileged ports, enabling non-root users to interact with NFS.

5. **Lack of Encryption**:
   - NFSv3 and earlier lack native encryption, exposing data to interception. NFSv4 with Kerberos mitigates this.

## Enumeration Techniques
### 1. Nmap
- **Scan for NFS Services**:
  ```bash
  sudo nmap 10.129.14.128 -p111,2049 -sV -sC
  ```
  Output:
  ```
  PORT    STATE SERVICE  VERSION
  111/tcp open  rpcbind  2-4 (RPC #100000)
  2049/tcp open  nfs      3-4 (RPC #100003)
  | nfs-ls: Volume /mnt/nfs
  | access: Read Lookup NoModify NoExtend NoDelete NoExecute
  | PERMISSION  UID   GID   SIZE  TIME                FILENAME
  | rwxrwxrwx   65534 65534 4096  2021-09-19T15:28:17 .
  | rw-r--r--   0     0     1872  2021-09-19T15:27:42 id_rsa
  | rw-r--r--   0     0     348   2021-09-19T15:28:17 id_rsa.pub
  | nfs-showmount:
  | /mnt/nfs 10.129.14.0/24
  ```
  - Identifies NFS version, shares, and file permissions.

- **NSE Scripts**:
  - `nfs-ls.nse`: Lists files and permissions.
  - `nfs-showmount.nse`: Displays exported shares.
  - `rpcinfo.nse`: Enumerates RPC services.

### 2. showmount
- Lists exported shares:
  ```bash
  showmount -e 10.129.14.128
  ```

### 3. Manual Mounting
- Mount and inspect shares to reveal files, UIDs, and GIDs, as shown above.

### 4. rpcinfo
- Enumerates RPC services:
  ```bash
  rpcinfo -p 10.129.14.128
  ```
  Output:
  ```
  program vers proto port  service
  100000  2,3,4 tcp   111   rpcbind
  100003  3,4   tcp   2049  nfs
  100005  1,2,3 tcp   45837 mountd
  ```

## Mitigation Strategies
1. **Use NFSv4 with Kerberos**:
   - Enables strong user authentication and encryption, reducing reliance on UID/GID mappings.

2. **Enable root_squash**:
   - Prevents clients from acting as root, mitigating privilege escalation risks.

3. **Restrict Access**:
   - Export shares to specific hosts (e.g., `192.168.1.10`) rather than subnets.
   - Use `ro` instead of `rw` unless write access is required.

4. **Disable Insecure Option**:
   - Avoid `insecure` to restrict NFS to privileged ports (<1024).

5. **Firewall Configuration**:
   - Allow only trusted IPs to access ports 111 and 2049.
   - For NFSv4, restrict to port 2049.

6. **Regular Auditing**:
   - Review `/etc/exports` with `exportfs -v` to verify configurations.
   - Monitor NFS access logs (`/var/log/nfsd`).

7. **Network Segmentation**:
   - Deploy NFS in isolated VLANs to limit exposure to untrusted clients.

8. **Patch Management**:
   - Keep NFS and RPC services updated to address vulnerabilities (e.g., CVE-2018-18281).

## Comparison with SMB, FTP, and TFTP
| **Feature**           | **NFS**                              | **SMB**                              | **FTP**                              | **TFTP**                             |
|-----------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|
| **Protocol**          | TCP/UDP (111, 2049)                 | TCP (139, 445)                      | TCP (20, 21)                        | UDP (69)                            |
| **Authentication**    | UID/GID, Kerberos (NFSv4)           | User credentials, guest access      | Credentials, anonymous access       | None                                |
| **Encryption**        | NFSv4 with Kerberos                 | SMB 3+ (AES-128)                    | FTPS (SSL/TLS)                      | None                                |
| **Reliability**       | TCP (reliable), UDP (less reliable) | Reliable (TCP)                      | Reliable (TCP)                      | Unreliable (UDP)                   |
| **Use Case**          | Unix file sharing                   | Windows file/printer sharing, AD    | General file transfers              | Simple file transfers (e.g., boot)  |
| **Security**          | Weak without Kerberos, root_squash critical | ACLs, encryption (SMB 3)            | Susceptible to sniffing if unencrypted | Minimal security, local networks only |
| **Enumeration**       | showmount, Nmap, rpcinfo            | smbclient, rpcclient, Nmap          | Nmap, ftp-anon.nse                  | Limited tools                       |

**Key Differences**:
- **NFS vs. SMB**: NFS is Unix-centric, relies on UID/GID or Kerberos, and lacks native authentication in older versions. SMB is Windows-centric, with robust ACLs and Active Directory integration.
- **NFS vs. FTP**: NFS provides seamless file system access, while FTP is designed for file transfers with explicit user authentication.
- **NFS vs. TFTP**: NFS is more complex and feature-rich, while TFTP is lightweight but insecure, suitable for simple transfers.

## Practical Example: Exploiting the `/mnt/nfs` Share
The document’s `/mnt/nfs` share is configured as:
```
/mnt/nfs 10.129.14.0/24(rw,sync,no_subtree_check)
```
**Vulnerabilities**:
- `rw`: Allows file modifications.
- Broad subnet access (`10.129.14.0/24`): Any host in the subnet can mount the share.
- No `root_squash` specified: Potentially allows root-level access (depends on default settings).

### Attack Scenario
1. **Enumerate Shares**:
   ```bash
   showmount -e 10.129.14.128
   ```
   Identifies `/mnt/nfs`.

2. **Mount Share**:
   ```bash
   mkdir target-NFS
   sudo mount -t nfs 10.129.14.128:/mnt/nfs target-NFS/ -o nolock
   ```

3. **Inspect Files**:
   ```bash
   ls -l target-NFS
   ```
   Reveals sensitive files like `id_rsa` and `cry0l1t3.priv`, which could be SSH private keys.

4. **Exploit with UID Spoofing**:
   - Create a local user with UID 1000 (matching `cry0l1t3`):
     ```bash
     sudo useradd -u 1000 attacker
     ```
   - Access files owned by UID 1000:
     ```bash
     su attacker
     cat target-NFS/cry0l1t3.priv
     ```
   - Use the private key for SSH access to the server.

5. **Privilege Escalation (if `no_root_squash`)**:
   - Upload a SUID binary:
     ```bash
     echo '#!/bin/bash\n/bin/bash' > target-NFS/root_shell
     chmod +s target-NFS/root_shell
     ```
   - Execute on the server to gain root access.

### Mitigation for `/mnt/nfs`
- Update `/etc/exports`:
  ```
  /mnt/nfs 10.129.14.10(ro,sync,root_squash,no_subtree_check)
  ```
  - Restricts to a single host (`10.129.14.10`).
  - Sets `ro` for read-only access.
  - Enables `root_squash` to prevent root access.
- Restart NFS:
  ```bash
  systemctl restart nfs-kernel-server
  ```
- Verify:
  ```bash
  exportfs -v
  ```

# DNS Notes

## Domain Name System (DNS)
- **Overview**: DNS translates human-readable domain names (e.g., `academy.hackthebox.com`) into IP addresses, enabling users to access servers without memorizing numerical addresses. Unlike NFS or SMB, DNS is not a file-sharing protocol but a distributed naming system critical to Internet functionality.
- **Purpose**: Resolves names to IPs (forward lookup) and IPs to names (reverse lookup), acting like a distributed phone book.
- **Operation**:
  - Operates over UDP/TCP port 53.
  - Uses a hierarchical, distributed database with no central authority.
  - Relies on various server types to resolve queries efficiently.

### DNS Server Types
| **Server Type**            | **Description**                                                                 |
|----------------------------|---------------------------------------------------------------------------------|
| **DNS Root Server**        | Manages top-level domains (TLDs) like `.com`, `.org`. Queried when name servers fail. |
| **Authoritative Name Server** | Provides definitive answers for specific domains, hosting zone files with records. |
| **Non-Authoritative Name Server** | Responds with cached or forwarded data, not directly responsible for a domain. |
| **Caching Server**         | Stores recent query results to reduce latency and load on upstream servers.      |
| **Forwarding Server**      | Forwards queries to other DNS servers, often used in internal networks.          |
| **Resolver**               | Client-side component that initiates DNS queries and handles responses.          |

### DNS Record Types
| **Record Type** | **Description**                                                                 |
|-----------------|---------------------------------------------------------------------------------|
| **A**           | Maps a hostname to an IPv4 address (e.g., `server1 IN A 10.129.14.5`).           |
| **AAAA**        | Maps a hostname to an IPv6 address.                                             |
| **CNAME**       | Aliases one hostname to another (e.g., `ftp IN CNAME server1`).                  |
| **MX**          | Specifies mail servers for a domain (e.g., `IN MX 10 mx.domain.com`).            |
| **NS**          | Indicates authoritative name servers for a domain (e.g., `IN NS ns1.domain.com`). |
| **SOA**         | Defines zone metadata (e.g., primary server, admin email, serial number).        |
| **PTR**         | Maps an IP address to a hostname for reverse lookups.                           |
| **TXT**         | Stores arbitrary text, often for verification or SPF records.                    |

## Configuration
- **Software**: Commonly uses BIND9 for DNS servers.
- **Configuration Files**:
  - **Named.conf**: Main configuration file, defines zones and options.
    ```bind
    zone "domain.com" {
      type master;
      file "/etc/bind/db.domain.com";
      allow-update { key rndc-key; };
    };
    ```
  - **Zone File**: Describes a DNS zone using BIND format (e.g., `/etc/bind/db.domain.com`).
    ```bind
    $ORIGIN domain.com
    $TTL 86400
    @ IN SOA dns1.domain.com. hostmaster.domain.com. (
        2001062501 ; serial
        21600      ; refresh after 6 hours
        3600       ; retry after 1 hour
        604800     ; expire after 1 week
        86400      ; minimum TTL of 1 day
    )
    @ IN NS ns1.domain.com.
    @ IN NS ns2.domain.com.
    @ IN MX 10 mx.domain.com.
    @ IN MX 20 mx.domain.com.
    @ IN A 10.129.14.5
    server1 IN A 10.129.14.5
    server2 IN A 10.129.14.7
    ns1 IN A 10.129.14.2
    ns2 IN A 10.129.14.3
    ftp IN CNAME server1
    mx IN CNAME server1
    mx2 IN CNAME server2
    www IN CNAME server2
    ```
  - **Reverse Zone File**: Maps IPs to hostnames using PTR records for reverse lookups.

- **Key Fields**:
  - **SOA**: Specifies the primary name server, admin contact, and timers (serial, refresh, retry, expire, minimum TTL).
  - **TTL**: Time-to-live for cached records (e.g., 86400 seconds = 1 day).
  - **$ORIGIN**: Sets the default domain for relative names.

### Reverse Lookup
- **Purpose**: Resolves IPs to hostnames using PTR records.
- **Example Reverse Zone File**:
  ```bind
  $ORIGIN 14.129.10.in-addr.arpa.
  $TTL 86400
  @ IN SOA dns1.domain.com. hostmaster.domain.com. (
      2001062501 ; serial
      21600      ; refresh
      3600       ; retry
      604800     ; expire
      86400      ; minimum TTL
  )
  @ IN NS ns1.domain.com.
  5 IN PTR server1.domain.com.
  7 IN PTR server2.domain.com.
  ```

## Practical Usage
### Querying DNS
1. **NS Query** (Name Servers):
   ```bash
   dig ns inlanefreight.htb @10.129.14.128
   ```
   Output:
   ```
   inlanefreight.htb. 604800 IN NS ns.inlanefreight.htb.
   ns.inlanefreight.htb. 604800 IN A 10.129.34.136
   ```

2. **Version Query** (CHAOS TXT):
   ```bash
   dig CH TXT version.bind @10.129.120.85
   ```
   Output:
   ```
   version.bind. 0 CH TXT "9.10.6-P1"
   version.bind. 0 CH TXT "9.10.6-P1-Debian"
   ```

3. **ANY Query** (All Records):
   ```bash
   dig any inlanefreight.htb @10.129.14.128
   ```
   Output:
   ```
   inlanefreight.htb. 604800 IN SOA inlanefreight.htb. root.inlanefreight.htb. ...
   inlanefreight.htb. 604800 IN TXT "MS=5973103/1"
   inlanefreight.htb. 604800 IN TXT "atlassian-domain-verification=..."
   inlanefreight.htb. 604800 IN TXT "v=spf1 include:mailgun.org ..."
   inlanefreight.htb. 604800 IN NS ns.inlanefreight.htb.
   ```

4. **Zone Transfer** (AXFR):
   ```bash
   dig axfr inlanefreight.htb @10.129.14.128
   ```
   Output (if allowed):
   ```
   inlanefreight.htb. 604800 IN SOA inlanefreight.htb. root.inlanefreight.htb. ...
   inlanefreight.htb. 604800 IN NS ns.inlanefreight.htb.
   app.inlanefreight.htb. 604800 IN A 10.129.18.15
   internal.inlanefreight.htb. 604800 IN A 10.129.18.15
   mail.inlanefreight.htb. 604800 IN A 10.129.18.201
   ns.inlanefreight.htb. 604800 IN A 10.129.34.136
   ```

5. **Subdomain Enumeration**:
   ```bash
   for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
       dig $sub.inlanefreight.htb @10.129.14.128 | grep -E "IN.*A"
   done
   ```
   Output:
   ```
   ns.inlanefreight.htb. 604800 IN A 10.129.34.136
   mail.inlanefreight.htb. 604800 IN A 10.129.18.201
   app.inlanefreight.htb. 604800 IN A 10.129.18.15
   ```

6. **DNSenum**:
   ```bash
   dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
   ```
   Output:
   ```
   ns.inlanefreight.htb. 604800 IN A 10.129.34.136
   mail.inlanefreight.htb. 604800 IN A 10.129.18.201
   app.inlanefreight.htb. 604800 IN A 10.129.18.15
   ```

## Security Risks
1. **Zone Transfer (AXFR) Exposure**:
   - Misconfigured servers allow unauthorized AXFR queries, revealing all zone records (e.g., `app.inlanefreight.htb`, `internal.inlanefreight.htb`).
   - Impact: Attackers map internal network infrastructure.

2. **Subdomain Enumeration**:
   - Exposed subdomains (e.g., `internal.inlanefreight.htb`) may reveal sensitive services or misconfigured servers.

3. **Version Disclosure**:
   - CHAOS TXT queries (e.g., `version.bind`) reveal BIND versions, aiding attackers in targeting known vulnerabilities (e.g., CVE-2020-8616).

4. **DNS Spoofing/Cache Poisoning**:
   - Unsecured DNS servers can be tricked into caching malicious records, redirecting users to attacker-controlled servers.

5. **DNS Amplification Attacks**:
   - Servers responding to ANY queries with large responses can be used in DDoS attacks due to amplification.

6. **Lack of DNSSEC**:
   - Without DNSSEC, responses are not cryptographically signed, increasing the risk of spoofing.

## Enumeration Techniques
1. **Nmap**:
   - Scan for DNS services:
     ```bash
     sudo nmap 10.129.14.128 -p53 -sV -sC
     ```
     Output:
     ```
     PORT   STATE SERVICE VERSION
     53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu)
     | dns-nsid:
     |   id.server: ns.inlanefreight.htb
     ```

2. **DIG**:
   - NS, ANY, AXFR, and version queries, as shown above.
   - Check for zone transfers:
     ```bash
     dig axfr inlanefreight.htb @10.129.14.128
     ```

3. **DNSenum**:
   - Automates subdomain brute-forcing, zone transfers, and version queries.

4. **Subdomain Brute-Forcing**:
   - Use wordlists to discover subdomains (e.g., `seclists/Discovery/DNS/subdomains-top1million-110000.txt`).

## Mitigation Strategies
1. **Restrict Zone Transfers**:
   - Configure `allow-transfer` in `named.conf`:
     ```bind
     zone "domain.com" {
       type master;
       file "/etc/bind/db.domain.com";
       allow-transfer { 10.129.14.2; 10.129.14.3; };
     };
     ```
   - Limit to specific IPs (e.g., secondary name servers).

2. **Disable Version Queries**:
   - Set `version none` in `named.conf`:
     ```bind
     options {
       version "none";
     };
     ```

3. **Implement DNSSEC**:
   - Enable DNSSEC to sign zone data, preventing spoofing:
     ```bind
     zone "domain.com" {
       dnssec-policy default;
     };
     ```

4. **Restrict ANY Queries**:
   - Limit responses to ANY queries to reduce amplification attack risks:
     ```bind
     options {
       allow-query { trusted; };
       minimal-any yes;
     };
     ```

5. **Firewall Rules**:
   - Allow DNS traffic (port 53) only from trusted sources:
     ```bash
     iptables -A INPUT -p udp --dport 53 -s 10.129.14.0/24 -j ACCEPT
     iptables -A INPUT -p udp --dport 53 -j DROP
     ```

6. **Use Rate Limiting**:
   - Prevent abuse with response rate limiting (RRL):
     ```bind
     options {
       rate-limit {
         responses-per-second 10;
       };
     };
     ```

7. **Patch Management**:
   - Regularly update BIND to address vulnerabilities (e.g., CVE-2021-25215).

8. **Network Segmentation**:
   - Isolate internal DNS servers (e.g., `internal.inlanefreight.htb`) from external access.

## Comparison with NFS, SMB, FTP, and TFTP
| **Feature**           | **DNS**                              | **NFS**                              | **SMB**                              | **FTP**                              | **TFTP**                             |
|-----------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|
| **Protocol**          | UDP/TCP (53)                        | TCP/UDP (111, 2049)                 | TCP (139, 445)                      | TCP (20, 21)                        | UDP (69)                            |
| **Purpose**           | Name resolution                     | Unix file sharing                   | Windows file/printer sharing        | File transfers                      | Simple file transfers               |
| **Authentication**    | None (DNSSEC for integrity)         | UID/GID, Kerberos (NFSv4)           | User credentials, guest access      | Credentials, anonymous              | None                                |
| **Encryption**        | DNSSEC (signing), DoT/DoH           | NFSv4 with Kerberos                 | SMB 3+ (AES-128)                    | FTPS (SSL/TLS)                      | None                                |
| **Reliability**       | UDP (fast, less reliable), TCP (reliable) | TCP (reliable), UDP (less reliable) | Reliable (TCP)                      | Reliable (TCP)                      | Unreliable (UDP)                   |
| **Security Risks**    | Zone transfers, spoofing, amplification | Weak auth, no_root_squash           | Guest access, weak passwords        | Plaintext credentials               | No security                         |
| **Enumeration**       | DIG, DNSenum, Nmap                  | showmount, Nmap, rpcinfo            | smbclient, rpcclient, Nmap          | Nmap, ftp-anon.nse                  | Limited tools                       |

**Key Differences**:
- **DNS vs. NFS/SMB**: DNS resolves names to IPs, while NFS/SMB share files. DNS has no native authentication, relying on DNSSEC for integrity.
- **DNS vs. FTP/TFTP**: DNS is for name resolution, not file transfer. FTP/TFTP require explicit authentication (except TFTP), while DNS queries are generally unauthenticated.

## Practical Example: Exploiting `inlanefreight.htb`
The document shows a DNS server at `10.129.14.128` with the zone `inlanefreight.htb`.

### Vulnerabilities
- **Zone Transfer Allowed**:
  - The `dig axfr` query reveals subdomains (`app`, `internal`, `mail`, `ns`), exposing internal network structure.
- **Subdomain Exposure**:
  - Subdomains like `internal.inlanefreight.htb` suggest sensitive internal services.
- **Version Disclosure**:
  - CHAOS TXT query could reveal BIND version, aiding vulnerability targeting.

### Attack Scenario
1. **Enumerate Name Servers**:
   ```bash
   dig ns inlanefreight.htb @10.129.14.128
   ```
   Identifies `ns.inlanefreight.htb` (10.129.34.136).

2. **Attempt Zone Transfer**:
   ```bash
   dig axfr inlanefreight.htb @10.129.14.128
   ```
   Reveals:
   - `app.inlanefreight.htb` (10.129.18.15)
   - `internal.inlanefreight.htb` (10.129.18.15)
   - `mail.inlanefreight.htb` (10.129.18.201)

3. **Brute-Force Subdomains**:
   ```bash
   dnsenum --dnsserver 10.129.14.128 --enum -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
   ```
   Confirms subdomains and their IPs.

4. **Exploit Internal Services**:
   - Target `internal.inlanefreight.htb` (10.129.18.15) for misconfigured services (e.g., web apps, NFS, SMB).
   - Check `mail.inlanefreight.htb` (10.129.18.201) for email-related vulnerabilities (e.g., open relays).

### Mitigation for `inlanefreight.htb`
- **Restrict Zone Transfers**:
  ```bind
  zone "inlanefreight.htb" {
    type master;
    file "/etc/bind/db.inlanefreight.htb";
    allow-transfer { none; };
  };
  ```
- **Hide Version**:
  ```bind
  options {
    version "none";
  };
  ```
- **Enable DNSSEC**:
  ```bind
  zone "inlanefreight.htb" {
    dnssec-policy default;
  };
  ```
- **Firewall**:
  ```bash
  iptables -A INPUT -p udp --dport 53 -s 10.129.14.0/24 -j ACCEPT
  iptables -A INPUT -p udp --dport 53 -j DROP
  ```

# SMTP Notes
### Simple Mail Transfer Protocol (SMTP) Overview

**Purpose**: SMTP is a protocol for sending emails across IP networks, operating between an email client (Mail User Agent, MUA) and an SMTP server (Mail Transfer Agent, MTA) or between two SMTP servers. It is often paired with IMAP or POP3 for retrieving emails.

**Operation**:
- **Ports**: Primarily uses TCP port 25 (unencrypted) or 587 (STARTTLS for encryption). Port 465 is sometimes used for SMTPS (SSL/TLS).
- **Client-Server Model**: SMTP operates as a client-server protocol, but servers can act as clients when relaying emails.
- **Encryption**: Unencrypted by default, transmitting commands and data in plaintext unless extended with ESMTP (Extended SMTP) using STARTTLS or SSL/TLS.
- **Authentication**: Supports SMTP-AUTH (e.g., AUTH PLAIN) to verify clients, typically after STARTTLS to protect credentials.
- **Components**:
  - **MUA**: Email client that sends emails to the MTA.
  - **MTA**: Core SMTP server software for sending/receiving emails.
  - **MSA**: Mail Submission Agent, validates email origins to reduce MTA load.
  - **MDA**: Mail Delivery Agent, transfers emails to recipient mailboxes.

**Key Commands**:
| **Command** | **Description** |
|-------------|-----------------------------------------------|
| `HELO`      | Initiates session with hostname.              |
| `EHLO`      | Initiates ESMTP session, lists extensions.    |
| `AUTH PLAIN`| Authenticates client with credentials.        |
| `MAIL FROM` | Specifies sender email address.               |
| `RCPT TO`   | Specifies recipient email address.            |
| `DATA`      | Initiates email content transmission.         |
| `VRFY`      | Verifies mailbox existence (often disabled).   |
| `EXPN`      | Expands mailing list (often disabled).        |
| `RSET`      | Resets session without closing connection.    |
| `NOOP`      | Requests server response to prevent timeout.   |
| `QUIT`      | Terminates session.                           |

**Limitations**:
- **No Delivery Confirmation**: SMTP does not guarantee standardized delivery notifications, often returning only error messages.
- **No Native Sender Authentication**: Allows fake sender addresses, enabling spam and spoofing.

### Configuration
The document provides a sample Postfix configuration for `mail.inlanefreight.htb`:
```plaintext
smtpd_banner = ESMTP Server
biff = no
append_dot_mydomain = no
compatibility_level = 2
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
myhostname = mail.inlanefreight.htb
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = $myhostname, localhost
masquerade_domains = $myhostname
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
smtp_helo_restrictions = reject_invalid_hostname
home_mailbox = /home/postfix
```

**Key Settings**:
- `mynetworks = 127.0.0.0/8 10.129.0.0/16`: Defines trusted networks allowed to relay emails.
- `smtp_bind_address = 0.0.0.0`: Listens on all interfaces.
- `smtp_tls_session_cache_database`: Enables TLS session caching for performance.
- `smtpd_banner = ESMTP Server`: Advertises ESMTP support.

**Dangerous Setting**:
- `mynetworks = 0.0.0.0/0`: Allows any IP to relay emails, creating an **open relay** vulnerability.

### Practical Usage
The document demonstrates interacting with the SMTP server at `10.129.14.128` using `telnet` and `nmap`.

1. **Session Initiation**:
   ```bash
   telnet 10.129.14.128 25
   ```
   Output:
   ```
   220 ESMTP Server
   HELO mail.inlanefreight.htb
   250 mail.inlanefreight.htb
   EHLO mail
   250-mail.inlanefreight.htb
   250-PIPELINING
   250-SIZE 10240000
   250-VRFY
   250-ETRN
   250-ENHANCEDSTATUSCODES
   250-8BITMIME
   250-DSN
   250-SMTPUTF8
   250-CHUNKING
   ```
   - `EHLO` reveals supported extensions, including `VRFY`, indicating potential user enumeration.

2. **User Enumeration with VRFY**:
   ```bash
   telnet 10.129.14.128 25
   VRFY root
   252 2.0.0 root
   VRFY cry0l1t3
   252 2.0.0 cry0l1t3
   VRFY testuser
   252 2.0.0 testuser
   ```
   - The server responds with `252` for all queries, suggesting `VRFY` is enabled but may not reliably confirm users (misconfiguration or anti-enumeration measure).

3. **Nmap Enumeration**:
   - **Basic Scan**:
     ```bash
     sudo nmap 10.129.14.128 -sC -sV -p25
     ```
     Output:
     ```
     PORT   STATE SERVICE VERSION
     25/tcp open  smtp    Postfix smtpd
     |_smtp-commands: mail.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
     ```
   - **Open Relay Test**:
     ```bash
     sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
     ```
     Output:
     ```
     PORT   STATE SERVICE
     25/tcp open  smtp
     |_smtp-open-relay: Server is an open relay (16/16 tests)
     ```
     - Confirms the server is an open relay, allowing unauthorized email relaying.

### Security Risks
1. **Open Relay**:
   - Misconfiguration (`mynetworks = 0.0.0.0/0`) allows anyone to relay emails, enabling spam, phishing, or spoofing.
   - Impact: Server can be blacklisted, disrupting legitimate email traffic.

2. **User Enumeration**:
   - Enabled `VRFY` or `EXPN` commands may leak valid usernames, aiding brute-force or phishing attacks.
   - Note: The document shows unreliable `VRFY` responses, reducing this risk.

3. **Plaintext Transmission**:
   - Without STARTTLS, commands, credentials, and email content are sent in plaintext, vulnerable to interception.

4. **Email Spoofing**:
   - Lack of sender authentication allows forging sender addresses, facilitating phishing.

5. **Spam and Blacklisting**:
   - Open relays are exploited for mass spam, leading to server blacklisting by email providers.

6. **No Delivery Confirmation**:
   - Inconsistent delivery notifications complicate tracking email status.

### Enumeration Techniques
1. **Telnet**:
   - Use `HELO`/`EHLO` to check server capabilities and `VRFY`/`EXPN` for user enumeration.
   - Example: `telnet 10.129.14.128 25`, then `VRFY root`.

2. **Nmap**:
   - `smtp-commands`: Lists supported commands (e.g., `VRFY`, `ETRN`).
   - `smtp-open-relay`: Tests for open relay vulnerabilities.
   - Example: `nmap --script smtp-open-relay 10.129.14.128 -p25`.

3. **SMTP User Enumeration Tools**:
   - Tools like `smtp-user-enum` automate `VRFY` queries with username lists:
     ```bash
     smtp-user-enum -M VRFY -U /path/to/usernames.txt -t 10.129.14.128
     ```

4. **Manual Spoofing Test**:
   - Attempt to send an email via `telnet` with a fake `MAIL FROM` to confirm open relay:
     ```bash
     telnet 10.129.14.128 25
     EHLO test
     MAIL FROM: <fake@domain.com>
     RCPT TO: <test@external.com>
     DATA
     Subject: Test
     This is a test email.
     .
     QUIT
     ```

### Mitigation Strategies
1. **Prevent Open Relay**:
   - Restrict `mynetworks` to trusted IPs:
     ```plaintext
     mynetworks = 127.0.0.0/8 10.129.0.0/16
     ```
   - Require authentication for relaying:
     ```plaintext
     smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject
     ```

2. **Disable VRFY/EXPN**:
   - Disable in Postfix:
     ```plaintext
     smtpd_noop_commands = vrfy, expn
     ```

3. **Enable STARTTLS**:
   - Enforce TLS for encryption:
     ```plaintext
     smtpd_tls_security_level = encrypt
     smtp_tls_security_level = encrypt
     ```

4. **Implement SPF, DKIM, DMARC**:
   - Add DNS records to validate sender domains:
     - **SPF** (TXT): `v=spf1 ip4:10.129.14.128 ~all`
     - **DKIM**: Sign emails with cryptographic keys.
     - **DMARC**: Enforce policies for failed validations.

5. **Firewall Rules**:
   - Restrict SMTP access to trusted IPs:
     ```bash
     iptables -A INPUT -p tcp --dport 25 -s 10.129.0.0/16 -j ACCEPT
     iptables -A INPUT -p tcp --dport 25 -j DROP
     ```

6. **Rate Limiting**:
   - Limit connections to prevent abuse:
     ```plaintext
     anvil_rate_time_unit = 60s
     smtpd_client_connection_rate_limit = 50
     ```

7. **Patch Management**:
   - Regularly update Postfix to address vulnerabilities (e.g., CVE-2020-6106).

8. **Monitor Logs**:
   - Check `/var/log/maillog` for unauthorized access or relay attempts.

### Comparison with DNS, NFS, SMB, FTP, TFTP
| **Feature**           | **SMTP**                             | **DNS**                              | **NFS**                              | **SMB**                              | **FTP**                              | **TFTP**                             |
|-----------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|
| **Protocol**          | TCP (25, 587, 465)                  | UDP/TCP (53)                        | TCP/UDP (111, 2049)                 | TCP (139, 445)                      | TCP (20, 21)                        | UDP (69)                            |
| **Purpose**           | Email sending                       | Name resolution                     | Unix file sharing                   | Windows file/printer sharing        | File transfers                      | Simple file transfers               |
| **Authentication**    | SMTP-AUTH, optional                 | None (DNSSEC for integrity)         | UID/GID, Kerberos (NFSv4)           | User credentials, guest access      | Credentials, anonymous              | None                                |
| **Encryption**        | STARTTLS, SSL/TLS (ESMTP)           | DNSSEC, DoT/DoH                     | NFSv4 with Kerberos                 | SMB 3+ (AES-128)                    | FTPS (SSL/TLS)                      | None                                |
| **Reliability**       | Reliable (TCP)                      | UDP (fast, less reliable), TCP (reliable) | TCP (reliable), UDP (less reliable) | Reliable (TCP)                      | Reliable (TCP)                      | Unreliable (UDP)                   |
| **Security Risks**    | Open relay, spoofing, plaintext     | Zone transfers, spoofing, amplification | Weak auth, no_root_squash           | Guest access, weak passwords        | Plaintext credentials               | No security                         |
| **Enumeration**       | Telnet, Nmap, smtp-user-enum        | DIG, DNSenum, Nmap                  | showmount, Nmap, rpcinfo            | smbclient, rpcclient, Nmap          | Nmap, ftp-anon.nse                  | Limited tools                       |

**Key Differences**:
- **SMTP vs. DNS**: SMTP sends emails, while DNS resolves names to IPs. SMTP supports optional authentication (SMTP-AUTH), unlike DNS, which relies on DNSSEC for integrity.
- **SMTP vs. NFS/SMB**: SMTP is for email, not file sharing. NFS/SMB require stronger authentication, while SMTP’s open relay risk is unique due to its relay function.
- **SMTP vs. FTP/TFTP**: SMTP transmits emails, not files. FTP supports authentication and encryption (FTPS), while TFTP lacks both, similar to unencrypted SMTP.

### Practical Example: Exploiting `inlanefreight.htb`
The SMTP server at `10.129.14.128` is identified as a Postfix server with an open relay vulnerability.

#### Vulnerabilities
- **Open Relay**:
  - Nmap confirms the server passes all 16 open relay tests, allowing unauthorized relaying.
- **VRFY Enabled**:
  - `VRFY` is supported but returns `252` for all queries, reducing enumeration reliability.
- **Plaintext Exposure**:
  - Lack of STARTTLS enforcement risks credential and email content interception.

#### Attack Scenario
1. **Confirm Open Relay**:
   ```bash
   telnet 10.129.14.128 25
   EHLO test
   MAIL FROM: <fake@domain.com>
   RCPT TO: <victim@external.com>
   DATA
   Subject: Phishing Test
   This is a fake email.
   .
   QUIT
   ```
   - If successful, the email is relayed, confirming the open relay.

2. **User Enumeration**:
   ```bash
   telnet 10.129.14.128 25
   VRFY root
   VRFY admin
   ```
   - Unreliable `252` responses limit enumeration effectiveness.

3. **Send Spam/Phishing**:
   - Use the open relay to send bulk emails with forged sender addresses:
     ```bash
     swaks --to victim@external.com --from ceo@inlanefreight.htb --server 10.129.14.128 --body "Urgent: Update your password"
     ```
   - Spoofed emails appear legitimate, increasing phishing success.

4. **Exploit with Other Services**:
   - Combine with DNS enumeration (e.g., `mail.inlanefreight.htb` from zone transfer) to target related services (e.g., IMAP/POP3 on `10.129.18.201`).

#### Mitigation for `inlanefreight.htb`
- **Fix Open Relay**:
  ```plaintext
  mynetworks = 127.0.0.0/8 10.129.0.0/16
  smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject
  ```
- **Disable VRFY**:
  ```plaintext
  smtpd_noop_commands = vrfy, expn
  ```
- **Enforce STARTTLS**:
  ```plaintext
  smtpd_tls_security_level = encrypt
  ```
- **Add SPF Record** (via DNS):
  ```bind
  inlanefreight.htb. 3600 IN TXT "v=spf1 ip4:10.129.14.128 ~all"
  ```
- **Firewall**:
  ```bash
  iptables -A INPUT -p tcp --dport 25 -s 10.129.0.0/16 -j ACCEPT
  iptables -A INPUT -p tcp --dport 25 -j DROP
  ```

### Integration with DNS
The DNS document (`inlanefreight.htb`) reveals the SMTP server’s details:
- **MX Record**: `mail.inlanefreight.htb` (10.129.18.201, not 10.129.14.128, suggesting multiple mail servers or misconfiguration).
- **Zone Transfer**: Exposes subdomains (`mail`, `app`, `internal`), aiding SMTP targeting.
- **Attack Synergy**:
  - Use DNS zone transfer to identify mail servers (`mail.inlanefreight.htb`).
  - Test SMTP open relay to send spoofed emails from `ceo@inlanefreight.htb`.
  - Target `internal.inlanefreight.htb` for related vulnerabilities (e.g., web apps).

---
# Internet Message Access Protocol (IMAP) Notes
### IMAP and POP3 Overview

**Purpose**:
- **IMAP**: A client-server protocol for managing emails on a remote server, supporting folder structures, synchronization across multiple clients, and online operations (e.g., searching, moving). Emails remain on the server until explicitly deleted.
- **POP3**: A simpler protocol for retrieving emails, designed to download and typically delete emails from the server (though retention is configurable). It lacks IMAP’s advanced features like folder management.

**Operation**:
- **Ports**:
  - IMAP: TCP 143 (unencrypted), 993 (IMAPS, SSL/TLS).
  - POP3: TCP 110 (unencrypted), 995 (POP3S, SSL/TLS).
- **Client-Server Model**: Both require authentication (username/password) to access mailboxes.
- **Communication**: Text-based ASCII commands. IMAP supports pipelining (multiple commands without waiting for responses) using identifiers.
- **Encryption**: Unencrypted by default, transmitting credentials and emails in plaintext unless SSL/TLS is used (IMAPS/POP3S).
- **Synchronization**:
  - IMAP: Synchronizes mailbox state across clients, with optional offline caching.
  - POP3: Downloads emails to the client, with no native synchronization.

**Key Features**:
- **IMAP**: Supports folder creation, multiple mailbox access, message flags (e.g., read/unread), and server-side searching.
- **POP3**: Limited to listing, retrieving, and deleting emails, with no folder support.

**IMAP Commands**:
| **Command**              | **Description**                                      |
|--------------------------|------------------------------------------------------|
| `LOGIN username password`| Authenticates user.                                  |
| `LIST "" *`              | Lists all mailboxes.                                 |
| `CREATE "INBOX"`         | Creates a mailbox.                                   |
| `DELETE "INBOX"`         | Deletes a mailbox.                                   |
| `RENAME "ToRead" "Important"` | Renames a mailbox.                              |
| `LSUB "" *`              | Lists subscribed mailboxes.                          |
| `SELECT INBOX`           | Selects a mailbox for operations.                    |
| `UNSELECT INBOX`         | Exits selected mailbox.                              |
| `FETCH <ID> all`         | Retrieves message data (e.g., headers, body).        |
| `CLOSE`                  | Closes mailbox, removing deleted messages.           |
| `LOGOUT`                 | Closes connection.                                   |

**POP3 Commands**:
| **Command**              | **Description**                                      |
|--------------------------|------------------------------------------------------|
| `USER username`          | Specifies username.                                  |
| `PASS password`          | Specifies password.                                  |
| `STAT`                   | Returns mailbox status (message count, size).        |
| `LIST`                   | Lists message IDs and sizes.                         |
| `RETR <ID>`              | Retrieves a message.                                 |
| `DELE <ID>`              | Marks a message for deletion.                        |
| `NOOP`                   | No operation, keeps connection alive.                |
| `QUIT`                   | Closes connection, deletes marked messages.          |

**Relationship with SMTP**:
- SMTP sends emails, while IMAP/POP3 retrieve them. IMAP can store sent emails in folders for multi-client access.

### Configuration
The document references **Dovecot** as a common IMAP/POP3 server but suggests experimenting with configurations on a local VM. A basic Dovecot configuration (`/etc/dovecot/dovecot.conf`) might include:
```plaintext
protocols = imap pop3
listen = *
mail_location = maildir:/var/mail/%u
auth_mechanisms = plain login
ssl = required
ssl_cert = </etc/ssl/certs/mailserver.crt
ssl_key = </etc/ssl/private/mailserver.key
```
- **Key Settings**:
  - `protocols`: Enables IMAP and POP3.
  - `ssl = required`: Enforces TLS encryption.
  - `mail_location`: Specifies mailbox storage (e.g., Maildir).
  - `auth_mechanisms`: Defines authentication methods (e.g., PLAIN, LOGIN).

### Practical Usage
The document demonstrates interacting with an IMAP/POP3 server using `nmap`, `curl`, and `openssl`.

1. **Nmap Scan**:
   ```bash
   sudo nmap 192.168.1.100 -sV -p110,143,993,995 -sC
   ```
   Output (hypothetical):
   ```
   PORT    STATE SERVICE  VERSION
   110/tcp open  pop3     Dovecot pop3d
   |_pop3-capabilities: AUTH-RESP-CODE SASL STLS TOP UIDL CAPA PIPELINING
   143/tcp open  imap     Dovecot imapd
   |_imap-capabilities: STARTTLS LITERAL+ LOGIN-REFERRALS OK
   993/tcp open  ssl/imap Dovecot imapd
   |_imap-capabilities: AUTH-PLAIN LITERAL+ LOGIN-REFERRALS OK
   995/tcp open  ssl/pop3 Dovecot pop3d
   |_pop3-capabilities: AUTH-RESP-CODE USER SASL(PLAIN) TOP UIDL CAPA PIPELINING
   ```
   - Confirms Dovecot services with TLS support.

2. **IMAP Interaction with Curl**:
   ```bash
   curl -k 'imaps://192.168.1.100' --user user:password -v
   ```
   Output (hypothetical):
   ```
   * Connected to 192.168.1.100 port 993
   * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
   * AOK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH-PLAIN]
   * AOK2 AUTHENTICATE PLAIN dXNlcjpwYXNzd29yZA==
   * AOK2 OK Logged in
   * AOK3 LIST
   * LIST (\HasNoChildren) "," INBOX
   * AOK3 OK List completed
   ```
   - Lists mailboxes (e.g., `INBOX`) after authentication.

3. **TLS Interaction with OpenSSL**:
   - **POP3S**:
     ```bash
     openssl s_client -connect 192.168.1.100:pop3s
     ```
     Output (hypothetical):
     ```
     +OK POP3 Server Ready
     ```
   - **IMAPS**:
     ```bash
     openssl s_client -connect 192.168.1.100:imaps
     ```
     Output (hypothetical):
     ```
     * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH-PLAIN]
     ```
   - Reveals TLS encryption details.

### Security Risks
1. **Plaintext Transmission**:
   - Unencrypted IMAP (143) or POP3 (110) exposes credentials and email content.
   - STARTTLS misconfigurations may allow fallback to plaintext.

2. **Weak Credentials**:
   - Simple passwords enable brute-force attacks.

3. **Self-Signed Certificates**:
   - Vulnerable to man-in-the-middle (MITM) attacks if clients accept invalid certificates.

4. **Credential Exposure**:
   - Compromised credentials grant access to sensitive emails (e.g., reset tokens, confidential data).

5. **Lack of Rate Limiting**:
   - Unlimited login attempts facilitate brute-force attacks.

6. **Exposed Services**:
   - Open IMAP/POP3 ports without IP restrictions increase attack surface.

### Enumeration Techniques
1. **Nmap**:
   - Scan for open ports and service details:
     ```bash
     nmap -sV -p110,143,993,995 192.168.1.100
     ```
   - Check capabilities:
     ```bash
     nmap --script imap-capabilities,pop3-capabilities 192.168.1.100 -p143,110
     ```

2. **Curl**:
   - Test credentials and list mailboxes:
     ```bash
     curl -k 'imaps://192.168.1.100' --user user:password
     ```

3. **OpenSSL**:
   - Inspect TLS certificates and banners:
     ```bash
     openssl s_client -connect 192.168.1.100:993
     ```

4. **Brute-Force Tools**:
   - Use `hydra` for credential attacks:
     ```bash
     hydra -L users.txt -P passwords.txt imap://192.168.1.100
     ```

5. **Manual Interaction**:
   - Test commands via `telnet` (unencrypted) or `openssl` (encrypted):
     ```bash
     telnet 192.168.1.100 143
     1 LOGIN user password
     1 LIST "" *
     ```

### Mitigation Strategies
1. **Enforce TLS**:
   - Disable unencrypted ports and require SSL/TLS:
     ```plaintext
     ssl = required
     disable_plaintext_auth = yes
     ```

2. **Use Valid Certificates**:
   - Use trusted CA certificates (e.g., Let’s Encrypt):
     ```plaintext
     ssl_cert = </etc/letsencrypt/live/mailserver/fullchain.pem
     ssl_key = </etc/letsencrypt/live/mailserver/privkey.pem
     ```

3. **Strong Authentication**:
   - Enforce complex passwords and consider MFA via external systems.

4. **Rate Limiting**:
   - Limit login attempts:
     ```plaintext
     auth_failure_delay = 5s
     auth_max_attempts = 3
     ```

5. **Firewall Rules**:
   - Restrict access to trusted IPs:
     ```bash
     iptables -A INPUT -p tcp -m multiport --dports 993,995 -s 192.168.1.0/24 -j ACCEPT
     iptables -A INPUT -p tcp -m multiport --dports 993,995 -j DROP
     ```

6. **Disable Unused Protocols**:
   - Disable POP3 if only IMAP is needed:
     ```plaintext
     protocols = imap
     ```

7. **Monitor Logs**:
   - Check `/var/log/dovecot.log` for unauthorized access.

8. **Patch Management**:
   - Update Dovecot to address vulnerabilities.

### Comparison with DNS, SMTP, NFS, SMB, FTP, TFTP
| **Feature**           | **IMAP/POP3**                        | **SMTP**                             | **DNS**                              | **NFS**                              | **SMB**                              | **FTP**                              | **TFTP**                             |
|-----------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|
| **Protocol**          | TCP (110, 143, 993, 995)            | TCP (25, 587, 465)                  | UDP/TCP (53)                        | TCP/UDP (111, 2049)                 | TCP (139, 445)                      | TCP (20, 21)                        | UDP (69)                            |
| **Purpose**           | Email retrieval                     | Email sending                       | Name resolution                     | Unix file sharing                   | Windows file/printer sharing        | File transfers                      | Simple file transfers               |
| **Authentication**    | Username/password                   | SMTP-AUTH, optional                 | None (DNSSEC for integrity)         | UID/GID, Kerberos (NFSv4)           | User credentials, guest access      | Credentials, anonymous              | None                                |
| **Encryption**        | SSL/TLS (IMAPS/POP3S)               | STARTTLS, SSL/TLS (ESMTP)           | DNSSEC, DoT/DoH                     | NFSv4 with Kerberos                 | SMB 3+ (AES-128)                    | FTPS (SSL/TLS)                      | None                                |
| **Reliability**       | Reliable (TCP)                      | Reliable (TCP)                      | UDP (fast, less reliable), TCP (reliable) | TCP (reliable), UDP (less reliable) | Reliable (TCP)                      | Reliable (TCP)                      | Unreliable (UDP)                   |
| **Security Risks**    | Plaintext, weak credentials, self-signed certs | Open relay, spoofing, plaintext     | Zone transfers, spoofing, amplification | Weak auth, no_root_squash           | Guest access, weak passwords        | Plaintext credentials               | No security                         |
| **Enumeration**       | Nmap, curl, openssl, hydra          | Telnet, Nmap, smtp-user-enum        | DIG, DNSenum, Nmap                  | showmount, Nmap, rpcinfo            | smbclient, rpcclient, Nmap          | Nmap, ftp-anon.nse                  | Limited tools                       |

**Key Differences**:
- **IMAP/POP3 vs. SMTP**: IMAP/POP3 retrieve emails, SMTP sends them. IMAP/POP3 require authentication, while SMTP may allow unauthenticated relaying.
- **IMAP/POP3 vs. DNS**: IMAP/POP3 manage emails, DNS resolves names. DNS lacks authentication, unlike IMAP/POP3.
- **IMAP/POP3 vs. NFS/SMB**: IMAP/POP3 are for email, not file sharing. NFS/SMB have different vulnerabilities (e.g., no_root_squash, guest access).
- **IMAP/POP3 vs. FTP/TFTP**: IMAP/POP3 retrieve emails, not files. FTP supports encryption (FTPS), while TFTP lacks security, similar to unencrypted IMAP/POP3.

### Practical Example: Exploiting a Generic Mail Server
Consider a mail server at `192.168.1.100` running Dovecot with IMAP/POP3 services.

#### Vulnerabilities
- **Self-Signed Certificate**: Risks MITM attacks.
- **Weak Credentials**: Simple passwords enable brute-forcing.
- **Unencrypted Ports**: Ports 143/110 expose plaintext data.
- **No Rate Limiting**: Allows brute-force attacks.

#### Attack Scenario
1. **Enumerate Services**:
   ```bash
   nmap -sV -p110,143,993,995 192.168.1.100
   ```
   - Confirms Dovecot IMAP/POP3.

2. **Brute-Force Credentials**:
   ```bash
   hydra -L users.txt -P passwords.txt imap://192.168.1.100
   ```
   - Finds valid credentials (e.g., `user:password`).

3. **Access Mailbox**:
   ```bash
   curl -k 'imaps://192.168.1.100' --user user:password
   ```
   - Lists mailboxes (e.g., `INBOX`).
   - Fetch emails:
     ```bash
     curl -k 'imaps://192.168.1.100/INBOX?ALL' --user user:password
     ```

4. **Exploit Email Content**:
   - Search for sensitive data (e.g., credentials, reset tokens).

5. **MITM Attack**:
   - Use `sslsplit` to intercept IMAPS/POP3S traffic if clients ignore certificate warnings.

6. **Synergy with SMTP/DNS**:
   - Exploit SMTP open relay to send phishing emails, tricking users into revealing IMAP/POP3 credentials.
   - Use DNS MX records to confirm mail server identity.

#### Mitigation
- **Enforce TLS**:
  ```plaintext
  ssl = required
  disable_plaintext_auth = yes
  ```
- **Use Trusted Certificate**:
  ```plaintext
  ssl_cert = </etc/letsencrypt/live/mailserver/fullchain.pem
  ssl_key = </etc/letsencrypt/live/mailserver/privkey.pem
  ```
- **Rate Limiting**:
  ```plaintext
  auth_failure_delay = 5s
  auth_max_attempts = 3
  ```
- **Firewall**:
  ```bash
  iptables -A INPUT -p tcp -m multiport --dports 993,995 -s 192.168.1.0/24 -j ACCEPT
  iptables -A INPUT -p tcp -m multiport --dports 993,995 -j DROP
  ```

### Integration with DNS and SMTP
- **DNS**: MX records identify mail servers, aiding IMAP/POP3 targeting. Zone transfers may reveal server details.
- **SMTP**: Complements IMAP/POP3 by handling email sending. Open relay vulnerabilities can be used to send phishing emails to steal IMAP/POP3 credentials.
