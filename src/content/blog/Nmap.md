---
title: "Nmap"
description: "Nmap (Network Mapper) is an open-source tool for network analysis and security auditing, written in C, C++, Python, and Lua."
pubDate: "Apr 20 2025"
heroImage: "/nmap.jpg"
---

## Introduction to Nmap
- **Overview**: Nmap (Network Mapper) is an open-source tool for network analysis and security auditing, written in C, C++, Python, and Lua.
- **Capabilities**:
  - Scans networks to identify available hosts using raw packets.
  - Detects services, applications, and their versions.
  - Identifies operating systems and versions.
  - Checks for packet filters, firewalls, or intrusion detection systems (IDS).
- **Use Cases**:
  - Network security auditing.
  - Simulating penetration tests.
  - Verifying firewall and IDS configurations.
  - Mapping networks and analyzing responses.
  - Identifying open ports and assessing vulnerabilities.

## Nmap Architecture
- **Scanning Techniques**:
  - Host discovery
  - Port scanning
  - Service enumeration and detection
  - OS detection
  - Scriptable interaction via Nmap Scripting Engine (NSE)

- **Syntax**:
  ```bash
  nmap <scan types> <options> <target>
  ```

## Scan Techniques
- **TCP Scans**:
  - **SYN Scan (-sS)**: Default, fast, sends SYN packet, does not complete TCP handshake.
    - Open port: Returns SYN-ACK.
    - Closed port: Returns RST.
    - Filtered: No response, possibly dropped by firewall.
  - **Connect Scan (-sT)**: Completes TCP three-way handshake, accurate but less stealthy, logs connections.
  - Other TCP scans: ACK (-sA), Window (-sW), Maimon (-sM), Null (-sN), FIN (-sF), Xmas (-sX).
- **UDP Scan (-sU)**: Slower due to stateless nature, no handshake, longer timeouts.
- **Other Scans**:
  - SCTP INIT/COOKIE-ECHO (-sY/-sZ)
  - IP protocol scan (-sO)
  - Idle scan (-sI)
  - FTP bounce scan (-b)
- **Custom Flags**: `--scanflags` for customized TCP scan flags.

### Example: TCP SYN Scan
```bash
sudo nmap -sS localhost
```
- **Output**:
  - Open ports: 22/tcp (ssh), 80/tcp (http), 5432/tcp (postgresql), 5901/tcp (vnc-1).
  - Closed ports: 996 not shown.

## Host Discovery
- **Purpose**: Identify active hosts before port scanning.
- **Methods**:
  - ICMP echo requests (-PE): Default ping scan.
  - ARP ping: Used in local networks, can be disabled with `--disable-arp-ping`.
- **Options**:
  - `-sn`: Disables port scanning, focuses on host discovery.
  - `-oA <filename>`: Saves results in all formats (normal, greppable, XML).
  - `-iL <file>`: Scans IPs from a provided list.
  - `--packet-trace`: Shows sent/received packets.
  - `--reason`: Explains why a host is marked alive.

### Example: Network Range Scan
```bash
sudo nmap 10.0.0.0/24 -sn -oA tnet
```
- **Output**: Lists active IPs (e.g., 10.0.0.4, 10.0.0.10, etc.).
- **Note**: Firewalls may block ICMP, requiring alternative techniques.

### Example: Single IP Scan
```bash
sudo nmap 10.0.0.18 -sn -oA host -PE --packet-trace
```
- **Output**: Confirms host is up via ICMP or ARP reply.

## Port Scanning
- **Port States**:
  - **Open**: Connection established (TCP, UDP, SCTP).
  - **Closed**: RST packet received (TCP).
  - **Filtered**: No response, likely firewall-protected.
  - **Unfiltered**: Accessible but state unclear (TCP-ACK scan).
  - **Open|Filtered**: No response, possibly open or filtered (UDP).
  - **Closed|Filtered**: Unclear if closed or filtered (Idle scan).
- **Default Behavior**:
  - Scans top 1000 TCP ports with SYN scan (-sS) if run as root.
  - Uses Connect scan (-sT) otherwise.
- **Port Selection**:
  - Specific ports: `-p 22,80,443`
  - Range: `-p 1-1000`
  - Top ports: `--top-ports 10`
  - All ports: `-p-`
  - Fast scan: `-F` (top 100 ports)

### Example: Top 10 TCP Ports
```bash
sudo nmap 10.0.0.28 --top-ports 10
```
- **Output**:
  - Open: 22/tcp (ssh), 25/tcp (smtp), 80/tcp (http), 110/tcp (pop3).
  - Closed: 21/tcp (ftp), 23/tcp (telnet), 443/tcp (https), 3389/tcp (ms-wbt-server).
  - Filtered: 139/tcp (netbios-ssn), 445/tcp (microsoft-ds).

### Example: Filtered Port
```bash
sudo nmap 10.0.0.28 -p 139 --packet-trace -Pn -n --disable-arp-ping
```
- **Output**: No response, port 139/tcp marked as filtered, likely due to firewall dropping packets.

### UDP Scanning
- **Challenges**:
  - Stateless protocol, no handshake.
  - Slower due to timeouts.
  - Empty datagrams may not elicit responses.
- **Port States**:
  - Open: Application responds.
  - Closed: ICMP port unreachable (type 3, code 3).
  - Open|Filtered: No response.
- **Example**:
  ```bash
  sudo nmap 10.0.0.28 -sU -p 137 --packet-trace --reason
  ```
  - **Output**: 137/udp open (netbios-ns) with UDP response.

## Service Version Detection
- **Option**: `-sV`
- **Purpose**: Identifies service names, versions, and additional details.
- **Example**:
  ```bash
  sudo nmap 10.0.0.28 -p 445 -sV --packet-trace --reason
  ```
  - **Output**: 445/tcp open, running Samba smbd 3.X - 4.X (workgroup: WORKGROUP), host: Ubuntu.

## Saving Results
- **Formats**:
  - Normal (`.nmap`): Human-readable.
  - Greppable (`.gnmap`): Script-friendly.
  - XML (`.xml`): Structured, convertible to HTML.
- **Option**: `-oA <filename>` saves in all formats.
- **Example**:
  ```bash
  sudo nmap 10.0.0.28 -p- -oA target
  ```
  - **Output Files**: `target.nmap`, `target.gnmap`, `target.xml`.
- **HTML Conversion**:
  ```bash
  xsltproc target.xml -o target.html
  ```
  - Creates a readable HTML report.

## Key Considerations
- **Stealth**:
  - SYN scan is stealthier than Connect scan due to incomplete handshake.
  - Modern IDS/IPS can detect both.
- **Firewalls**:
  - May drop or reject packets, affecting results.
  - Use `--packet-trace` and `--reason` to diagnose.
- **Performance**:
  - UDP scans are slower than TCP.
  - Use `-F` or `--top-ports` for faster scans.
- **Documentation**:
  - Always save results for comparison and reporting.
  - XML format is ideal for generating professional reports.

## Resources
- Port scanning techniques: [Nmap Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- Host discovery strategies: [Nmap Host Discovery Strategies](https://nmap.org/book/man-host-discovery.html)

## Service Enumeration

### **Overview**: Identifying the exact application and version running on open ports is critical for finding vulnerabilities and exploits.

- **Purpose**:
  - Determine service versions to search for known vulnerabilities.
  - Analyze source code for specific versions.
  - Find precise exploits matching the service and OS.

### **Service Version Detection**

- **Option**: `-sV`
- **Strategy**:
  - Perform a quick port scan (e.g., `-F` or `--top-ports`) to identify open ports with minimal traffic.
  - Run a full port scan (`-p-`) in the background for comprehensive results.
  - Use `-sV` on specific ports to detect service versions.
- **Monitoring**:
  - Press **Space Bar** during scan to check status.
  - Use `--stats-every 5s` for periodic progress updates.
  - Increase verbosity (`-v` or `-vv`) to display open ports as they are found.

- **Example**:

  ```bash
  sudo nmap 10.0.0.28 -p- -sV -v
  ```

  - **Output**:
    - Open ports: 22/tcp (OpenSSH 7.6p1 Ubuntu), 25/tcp (Postfix smtpd), 80/tcp (Apache 2.4.29), 110/tcp (Dovecot pop3d), 143/tcp (Dovecot imapd), 993/tcp (Dovecot imapd SSL), 995/tcp (Dovecot pop3d SSL).
    - Filtered: 139/tcp (netbios-ssn), 445/tcp (microsoft-ds).
    - Service Info: Host: inlane, OS: Linux, CPE: cpe:/o:linux:linux_kernel.

### **Banner Grabbing**

- **Purpose**: Extract service banners to gather additional details (e.g., OS distribution).
- **Limitations**:
  - Nmap may miss banner details if it cannot interpret them.
  - Some services may not send banners or have manipulated banners.
- **Manual Verification**:
  - Use tools like `nc` (netcat) to connect to services and grab banners.
  - Monitor traffic with `tcpdump` to capture full responses.

- **Example**:

  ```bash
  nc -nv 10.0.0.28 25
  ```

  - **Output**: `220 inlane ESMTP Postfix (Ubuntu)` (reveals Ubuntu distribution).

  ```bash
  sudo tcpdump -i eth0 host 10.10.14.2 and 10.0.0.28
  ```

  - **Output**: Captures TCP handshake and PSH-ACK packet with banner data.

## Nmap Scripting Engine (NSE)

### **Overview**: NSE allows Lua scripts to interact with services, enhancing Nmap’s functionality.

- **Script Categories**:
  - **auth**: Tests authentication credentials.
  - **broadcast**: Discovers hosts via broadcasting.
  - **brute**: Attempts credential brute-forcing.
  - **default**: Runs with `-sC` option.
  - **discovery**: Evaluates accessible services.
  - **dos**: Checks for DoS vulnerabilities (use cautiously).
  - **exploit**: Tests for known vulnerabilities.
  - **external**: Uses external services for processing.
  - **fuzzer**: Identifies vulnerabilities via unexpected packets.
  - **intrusive**: Aggressive scripts that may disrupt services.
  - **malware**: Detects malware infections.
  - **safe**: Non-disruptive scripts.
  - **version**: Extends version detection.
  - **vuln**: Checks for known vulnerabilities.

### **Running Scripts**

- **Options**:
  - `--script <script-name>`: Run specific scripts.
  - `--script <category>`: Run all scripts in a category.
  - `-sC`: Run default scripts.
  - `-A`: Aggressive scan (includes `-sV`, `-O`, `--traceroute`, `-sC`).

- **Example: Specific Scripts**

  ```bash
  sudo nmap 10.0.0.28 -p 25 --script banner,smtp-commands
  ```

  - **Output**:
    - Banner: `220 inlane ESMTP Postfix (Ubuntu)` (confirms Ubuntu).
    - SMTP commands: PIPELINING, SIZE, VRFY, ETRN, STARTTLS, etc.
    - Useful for identifying valid users or server capabilities.

- **Example: Aggressive Scan**

  ```bash
  sudo nmap 10.0.0.28 -p 80 -A
  ```

  - **Output**:
    - Service: Apache 2.4.29 (Ubuntu), WordPress 5.3.4.
    - OS guesses: Linux 2.6.32–4.9 (96% confidence).
    - Traceroute: 1 hop.

- **Example: Vulnerability Scan**

  ```bash
  sudo nmap 10.0.0.28 -p 80 -sV --script vuln
  ```

  - **Output**:
    - WordPress 5.3.4 detected, admin folder (`/wp-login.php`), user: admin.
    - Apache 2.4.29 vulnerabilities: CVE-2019-0211 (7.2), CVE-2018-1312 (6.8), CVE-2017-15715 (6.8).
    - No stored XSS found.

- **Resource**: NSE documentation at [Nmap NSE Documentation](https://nmap.org/nsedoc/index.html).

## Performance Optimization

### **Overview**: Optimize Nmap scans for speed, especially on large networks or low-bandwidth environments.

- **Key Options**:
  - **Timeouts**:
    - `--initial-rtt-timeout <time>`: Initial timeout (default: 100ms).
    - `--max-rtt-timeout <time>`: Maximum timeout.
  - **Retries**:
    - `--max-retries <number>`: Number of packet retries (default: 10).
  - **Rates**:
    - `--min-rate <number>`: Minimum packets per second.
  - **Timing Templates**:
    - `-T0` (paranoid) to `-T5` (insane), with `-T3` (normal) as default.

### **Examples**

- **Optimized RTT**:

  ```bash
  sudo nmap 10.0.0.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
  ```

  - **Result**: Scan time reduced from 39.44s to 12.29s, but missed 2 hosts due to short timeout.

- **Reduced Retries**:

  ```bash
  sudo nmap 10.0.0.0/24 -F --max-retries 0
  ```

  - **Result**: Found 21 open ports vs. 23 with default retries, faster but less reliable.

- **Packet Rate**:

  ```bash
  sudo nmap 10.0.0.0/24 -F --min-rate 300 -oN tnet.minrate300
  ```

  - **Result**: Scan time reduced from 29.83s to 8.67s, same 23 open ports.

- **Timing Template**:

  ```bash
  sudo nmap 10.0.0.0/24 -F -T5 -oN tnet.T5
  ```

  - **Result**: Scan time reduced from 32.44s to 18.87s, same 23 open ports.

### **Considerations**:
- Aggressive settings (`-T5`, low retries) may trigger security systems.
- Balance speed and accuracy based on network conditions.
- White-box tests allow higher rates if whitelisted.

## Firewall and IDS/IPS Evasion

### **Overview**: Nmap provides techniques to bypass firewalls and avoid detection by IDS/IPS.

- **Firewalls**:
  - Monitor and filter traffic based on rules.
  - Drop (no response) or reject (RST or ICMP error) packets.
  - Common ICMP errors: Net/Host/Port Unreachable, Net/Host/Proto Prohibited.

- **IDS/IPS**:
  - **IDS**: Passively monitors for attack patterns, alerts administrators.
  - **IPS**: Actively blocks detected threats.
  - Detection based on signatures or anomalies (e.g., aggressive scans).

### **Evasion Techniques**

- **TCP ACK Scan (-sA)**:
  - Sends ACK-only packets, harder to filter as firewalls may assume an existing connection.
  - Open/closed ports return RST; filtered ports return no response.

  ```bash
  sudo nmap 10.0.0.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
  ```

  - **Output**: 22/tcp unfiltered (ssh), 21/tcp and 25/tcp filtered.

- **Decoys (-D)**:
  - Spoofs packets with random or specified IP addresses to mask the source.
  - Requires decoy IPs to be alive to avoid SYN-flood protections.

  ```bash
  sudo nmap 10.0.0.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
  ```

  - **Output**: Port 80/tcp open, scan appears to come from multiple IPs.

- **Source IP Spoofing (-S)**:
  - Specify a trusted or internal IP to bypass subnet restrictions.

  ```bash
  sudo nmap 10.0.0.28 -n -Pn -p 445 -O -S 10.0.0.200 -e tun0
  ```

  - **Output**: 445/tcp open (microsoft-ds), OS guesses: Linux 2.6.32–4.9.

- **Source Port Manipulation (--source-port)**:
  - Use trusted ports (e.g., 53 for DNS) to bypass firewall rules.

  ```bash
  sudo nmap 10.0.0.28 -p 50000 -sS -Pn -n --disable-arp-ping --source-port 53
  ```

  - **Output**: 50000/tcp open (ibm-db2), bypassed firewall.

- **DNS Proxying (--dns-servers)**:
  - Use internal DNS servers to interact with DMZ or internal hosts.
  - DNS queries (UDP/TCP 53) are often trusted.

### **Detecting IDS/IPS**

- **Challenges**:
  - Passive monitoring makes detection difficult.
  - IPS may block IPs without warning.
- **Techniques**:
  - Use multiple VPS IPs; if one is blocked, an IPS is likely present.
  - Perform aggressive scans (e.g., single-port hammering) to trigger administrator actions.
- **Mitigation**:
  - Use quieter scans (e.g., `-T2`, decoys).
  - Rotate VPS IPs to avoid blocks.

### **Considerations**:
- Spoofed packets may be filtered by ISPs or routers.
- Test firewall rules incrementally to avoid detection.
- Use `--packet-trace` and `--reason` to analyze firewall behavior.

## Key Considerations

- **Stealth**:
  - Use `-sS`, `-sA`, or decoys for stealthier scans.
  - Avoid `-A` or `-T5` in black-box tests to reduce detection risk.
- **Accuracy**:
  - Manual banner grabbing (`nc`, `tcpdump`) complements Nmap’s `-sV`.
  - NSE scripts (`vuln`, `exploit`) enhance vulnerability detection.
- **Performance**:
  - Optimize timeouts, retries, and rates for large networks.
  - Use `-F` or `--top-ports` for quick reconnaissance.
- **Evasion**:
  - Combine decoys, source IP/port manipulation, and ACK scans to bypass protections.
  - Monitor scan traffic to detect IPS blocks.

## Resources

- NSE scripts: [Nmap NSE Documentation](https://nmap.org/nsedoc/index.html)
- Firewall evasion: [Nmap Firewall Evasion Techniques](https://nmap.org/book/man-bypass-firewalls-ids.html)

