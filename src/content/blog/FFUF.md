---
title: "FFUF"
description: "A fast web fuzzer written in Go."
pubDate: "May 09 2025"
heroImage: "/ffuf.png"
---

# Notes on Introduction to Attacking Web Applications with Ffuf

## Overview
- Module centers on web fuzzing using the `ffuf` tool, recognized for its reliability and widespread use in directory and parameter brute-forcing.
- Ffuf automates the process of testing web application components by sending requests to identify existing resources.

## Topics Covered
- **Fuzzing for Directories**: Discovering accessible directories on a web server.
- **Fuzzing for Files and Extensions**: Detecting files and specific extensions (e.g., `.php`, `.txt`).
- **Identifying Hidden VHosts**: Uncovering virtual hosts that are not directly exposed.
- **Fuzzing for PHP Parameters**: Identifying valid PHP parameters within web applications.
- **Fuzzing for Parameter Values**: Testing various parameter values to reveal hidden features or vulnerabilities.

## Methodology
- **Fuzzing Process**: Utilizes wordlists to send requests to a web server, checking for responses like HTTP 200 to confirm the existence of pages or resources.
- **Manual Analysis**: Resources identified (e.g., pages, files) require manual inspection for deeper investigation or exploitation.

## Tools
- **Ffuf**: A fast and dependable tool for automated web fuzzing tasks.
</xaiArtifact>

# Notes on Web Fuzzing

## Introduction
- Focuses on using the `ffuf` tool to fuzz websites for directories, starting with a basic exercise on a website with no visible links or navigation clues.
- Example: Website at `http://<SERVER_IP>` displays "Welcome to HTB Academy" but lacks links, necessitating fuzzing to discover hidden pages.

## Fuzzing Overview
- **Definition**: A testing technique that sends various inputs to an interface to observe reactions.
  - **SQL Injection**: Send special characters to detect vulnerabilities.
  - **Buffer Overflow**: Send incrementally longer strings to crash binaries.
  - **Web Fuzzing**: Use wordlists of common terms to identify existing web pages or directories.
- **Purpose**: Web servers rarely list all links; fuzzing checks for valid pages by analyzing HTTP response codes.
  - **HTTP 404 (Not Found)**: Page does not exist (e.g., `https://www.hackthebox.eu/doesnotexist`).
  - **HTTP 200 (OK)**: Page exists (e.g., `https://www.hackthebox.eu/login`).
- **Automation**: Tools like `ffuf` send hundreds of requests per second, analyzing HTTP codes to identify valid resources efficiently.

## Wordlists
- **Role**: Similar to password dictionary attacks, wordlists contain commonly used terms for web directories and pages.
- **Effectiveness**: May not find all pages (e.g., randomly named ones), but achieves up to 90% success on some websites.
- **Sources**:
  - **SecLists**: GitHub repository (`/opt/useful/SecLists` on Pwnbox) with categorized wordlists for fuzzing, including passwords for brute-forcing.
  - **Directory Wordlist**: `directory-list-2.3-small` located at `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`.
- **Tip**: Wordlists may include copyright comments at the start, which can clutter results. Use `ffuf` with appropriate flags to skip these lines.
</xaiArtifact>


# Notes on Directory Fuzzing

## Introduction
- Builds on web fuzzing concepts, focusing on using `ffuf` to discover website directories.
- Assumes familiarity with wordlists (e.g., `directory-list-2.3-small`) and the need to identify hidden directories on a web server.

## Ffuf Tool
- **Availability**: Pre-installed on Pwnbox; install on other systems via `apt install ffuf` or GitHub repository.
- **Help Command**: `ffuf -h` displays options, including:
  - **HTTP Options**:
    - `-H`: Add headers (e.g., `Name: Value`).
    - `-X`: Specify HTTP method (default: GET).
    - `-b`: Cookie data.
    - `-d`: POST data.
    - `-u`: Target URL.
    - `-recursion`: Enable recursive scanning (FUZZ keyword only).
    - `-recursion-depth`: Set maximum recursion depth (default: 0).
  - **Matcher Options**:
    - `-mc`: Match HTTP status codes (default: 200, 204, 301).
    - `-ms`: Match response size.
  - **Filter Options**:
    - `-fc`: Filter HTTP status codes.
    - `-fs`: Filter response size.
  - **Input Options**:
    - `-w`: Wordlist path and optional keyword (e.g., `/path:FUZZ`).
  - **Output Options**:
    - `-o`: Save output to file.
  - **Example**:
    ```bash
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
    ```
    Fuzzes paths, matches all responses, filters size 42, with colored verbose output.

## Directory Fuzzing Process
- **Setup**:
  - Select wordlist: `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`.
  - Assign keyword (e.g., `FUZZ`) to wordlist:
    ```bash
    ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
    ```
  - Place `FUZZ` in URL where directory is expected:
    ```bash
    ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ
    ```
- **Execution**:
  - Final command tests ~90,000 URLs in under 10 seconds (speed varies by network).
  - Example:
    ```bash
    ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ
    ```
- **Performance Tuning**:
  - Increase threads (e.g., `-t 200`) for speed, but risks Denial of Service or network disruption; not recommended for remote sites.
- **Results**:
  - Identifies directories like `http://<SERVER_IP>:<PORT>/blog`.
  - Example result: `/blog` returns an empty page (no HTTP 404/403), indicating access but no dedicated page.

## Next Steps
- Investigate discovered directories (e.g., `/blog`) for hidden files or pages in subsequent fuzzing tasks.


# Notes on Page Fuzzing

## Introduction
- Builds on `ffuf` usage with wordlists and keywords to locate pages within directories.
- Scenario: Continues from discovering the `/blog` directory, which appears empty, requiring fuzzing to find hidden pages.

## Extension Fuzzing
- **Purpose**: Identify the file extensions used by the website (e.g., `.html`, `.php`, `.aspx`) to focus page fuzzing.
- **Challenges**:
  - Guessing extensions based on server type (e.g., Apache → `.php`, IIS → `.asp`/`.aspx`) is unreliable.
  - Manual inspection of HTTP response headers may provide clues but is inefficient.
- **Solution**: Use `ffuf` to fuzz extensions with a dedicated wordlist.
- **Wordlist**: `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt` (includes dot, e.g., `.php`).
- **Approach**:
  - Use a common file like `index` to test extensions, avoiding the need to fuzz both filenames and extensions simultaneously.
  - Place `FUZZ` keyword where the extension belongs in the URL.
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://<SERVER_IP>:<PORT>/blog/indexFUZZ
  ```
- **Ffuf Configuration**:
  - Method: GET
  - Threads: 5
  - Timeout: 10 seconds
  - Matcher: HTTP status codes 200, 204, 301, 302, 307, 401, 403
  - Follow Redirects: False
  - Calibration: False
- **Results**:
  - `.php`: HTTP 200 (valid, size: 0, empty page).
  - `.phps`: HTTP 403 (access denied, size: 283).
  - Total: 39 extensions tested.
- **Conclusion**: Website uses PHP, enabling targeted page fuzzing with `.php` extension.

## Page Fuzzing
- **Objective**: Find PHP pages in the `/blog` directory using the same wordlist as directory fuzzing.
- **Wordlist**: `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`.
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/blog/FUZZ.php
  ```
- **Ffuf Configuration**:
  - Method: GET
  - Threads: 40
  - Timeout: 10 seconds
  - Matcher: HTTP status codes 200, 204, 301, 302, 307, 401, 403
  - Follow Redirects: False
  - Calibration: False
- **Results**:
  - `index.php`: HTTP 200 (size: 0, empty page).
  - `[REDACTED].php`: HTTP 200 (size: 465, contains content, 42 words, 15 lines).
  - Total: 87,651 URLs tested in ~15 seconds (~5,843 req/sec).
- **Verification**:
  - Visit `http://<SERVER_IP>:<PORT>/blog/[REDACTED].php` to confirm content.
  - `index.php` is empty, but `[REDACTED].php` has accessible content.

## Next Steps
- Manually inspect discovered pages (e.g., `[REDACTED].php`) for vulnerabilities or further exploration.


# Notes on Recursive Fuzzing

## Introduction
- Addresses the inefficiency of manually fuzzing directories and subdirectories sequentially, especially for websites with complex directory structures (e.g., `/login/user/content/uploads/`).
- Introduces **recursive fuzzing** to automate scanning of directories and their subdirectories.

## Recursive Fuzzing Overview
- **Definition**: Automatically scans newly identified directories for pages and subdirectories, continuing until all specified levels are covered.
- **Challenges**:
  - Large directory trees can significantly increase scan time and resource usage.
  - Requires careful configuration to avoid excessive requests or network strain.
- **Solution**: Use recursion with a specified depth to limit scanning to manageable levels.

## Ffuf Recursive Flags
- **Flags**:
  - `-recursion`: Enables recursive scanning, starting new scans for discovered directories.
  - `-recursion-depth <n>`: Limits recursion to `n` levels (e.g., `-recursion-depth 1` scans main directories and their immediate subdirectories only).
  - `-e <extension>`: Specifies file extensions (e.g., `-e .php`) for page fuzzing, assuming site-wide consistency.
  - `-v`: Outputs full URLs for clarity, distinguishing files across directories.
- **Note**: Extensions like `.php` are typically uniform across a site, simplifying fuzzing.

## Recursive Scanning Example
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ -recursion -recursion-depth 1 -e .php -v
  ```
- **Ffuf Configuration**:
  - Method: GET
  - Wordlist: `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`
  - Extensions: `.php`
  - Threads: 40
  - Timeout: 10 seconds
  - Matcher: HTTP status codes 200, 204, 301, 302, 307, 401, 403
  - Follow Redirects: False
  - Calibration: False
- **Results**:
  - Discovered directories: `/blog`, `/forum`.
  - Files:
    - `http://<SERVER_IP>:<PORT>/index.php` (Status: 200, Size: 986).
    - `http://<SERVER_IP>:<PORT>/forum/index.php` (Status: 200, Size: 0).
  - Other hits include previously identified pages and new subdirectories.
  - Scan characteristics:
    - Longer duration due to recursive checks.
    - ~6x more requests than non-recursive scans.
    - Wordlist effectively doubled (with and without `.php`).
- **Sample Output**:
  ```
  [Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://<SERVER_IP>:<PORT>/index.php
  [INFO] Adding a new job to the queue: http://<SERVER_IP>:<PORT>/forum/FUZZ
  [Status: 301, Size: 326, Words: 20, Lines: 10] | URL | http://<SERVER_IP>:<PORT>/blog
  [Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://<SERVER_IP>:<PORT>/forum/index.php
  ```

## Key Observations
- **Efficiency**: Single command retrieves all previous results plus additional subdirectories and pages.
- **Strategic Use**: Start with shallow recursion (e.g., `-recursion-depth 1`), then focus deeper scans on interesting directories to optimize time and resources.


# Notes on DNS Records

## Introduction
- Context: After accessing `/blog` directory, a message indicates the admin panel has moved to `academy.htb`.
- Issue: Attempting to visit `http://academy.htb:<PORT>` results in a "can't connect to the server" error.

## Problem Analysis
- **Browser Behavior**:
  - Browsers resolve URLs to IPs using:
    1. Local `/etc/hosts` file.
    2. Public DNS servers (e.g., Google’s 8.8.8.8).
  - `academy.htb` is not a public website and is not listed in public DNS or the local `/etc/hosts`, causing connection failure.
- **Direct IP Access**: Visiting the server’s IP directly works, but using `academy.htb` fails due to unresolved DNS.

## Solution: Modify /etc/hosts
- **Command**:
  ```bash
  sudo sh -c 'echo "<SERVER_IP> academy.htb" >> /etc/hosts'
  ```
- **Effect**: Maps `academy.htb` to the target server’s IP, allowing the browser to resolve the URL.
- **Verification**:
  - Visit `http://academy.htb:<PORT>`; displays "Welcome to HTB Academy" (same as direct IP access).
  - Access `http://academy.htb:<PORT>/blog/index.php` to confirm it’s the same domain.

## Observations
- **Domain Equivalence**: `academy.htb` resolves to the same website as the direct IP, indicating it’s the same server.
- **Fuzzing Results**: Previous recursive scans on the IP did not reveal admin panels or related directories.
- **Next Steps**: Investigate subdomains under `*.academy.htb` to locate the admin panel, covered in the next section.


# Notes on Sub-domain Fuzzing

## Introduction
- Focuses on using `ffuf` to identify subdomains (e.g., `photos.google.com` as a subdomain of `google.com`) for a target website.
- Subdomains are checked for existence by verifying if they resolve to a valid server IP via DNS records.

## Requirements
- **Wordlist**: A list of common subdomain names.
  - Location: `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` (shorter list for efficiency; larger lists available for broader scans).
- **Target**: The domain to fuzz for subdomains (e.g., `inlanefreight.com` or `academy.htb`).

## Sub-domain Fuzzing Process
- **Methodology**:
  - Place the `FUZZ` keyword in the subdomain position of the URL (e.g., `https://FUZZ.domain.com`).
  - Use `ffuf` to send requests and check for valid HTTP responses indicating active subdomains.
- **Example 1: inlanefreight.com**:
  - Command:
    ```bash
    ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
    ```
  - **Ffuf Configuration**:
    - Method: GET
    - Threads: 40
    - Timeout: 10 seconds
    - Matcher: HTTP status codes 200, 204, 301, 302, 307, 401, 403, 405
    - Follow Redirects: False
    - Calibration: False
  - **Results**:
    - `support.inlanefreight.com`: HTTP 301
    - `ns3.inlanefreight.com`: HTTP 301
    - `blog.inlanefreight.com`: HTTP 301
    - `my.inlanefreight.com`: HTTP 301
    - `www.inlanefreight.com`: HTTP 200 (Size: 22,266, Words: 2,903, Lines: 316)
  - **Observation**: Multiple subdomains identified, with `www` returning a substantial page.

- **Example 2: academy.htb**:
  - Command:
    ```bash
    ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.academy.htb/
    ```
  - **Ffuf Configuration**:
    - Method: GET
    - Threads: 40
    - Timeout: 10 seconds
    - Matcher: HTTP status codes 200, 204, 301, 302, 307, 401, 403
    - Follow Redirects: False
    - Calibration: False
    - Progress: 4,997 requests (~131 req/sec)
  - **Results**: No hits returned.
  - **Reason**:
    - `academy.htb` is not a public domain and lacks public DNS records.
    - Although `academy.htb` was added to `/etc/hosts`, subdomains (e.g., `admin.academy.htb`) are not included, and public DNS queries fail.

## Key Insights
- **No Hits ≠ No Subdomains**: Lack of results for `academy.htb` indicates no public DNS records, not an absence of subdomains.
- **Local Environment Limitation**: Since `academy.htb` is a local HTB domain, subdomains may exist but require manual `/etc/hosts` updates or alternative discovery methods (e.g., VHost fuzzing, covered later).


# Notes on VHost Fuzzing

## Introduction
- Addresses limitations of subdomain fuzzing for non-public domains (e.g., `academy.htb`), where public DNS records are unavailable.
- Introduces **VHost (Virtual Host) fuzzing** to identify subdomains and virtual hosts served on the same IP, including those without public DNS records.

## VHosts vs. Sub-domains
- **Sub-domains**: Distinct domains under a parent domain (e.g., `photos.google.com` under `google.com`), typically with public DNS records.
- **VHosts**: Multiple websites (subdomains or domains) served on the same server/IP, which may or may not have public DNS records.
- **Key Difference**: VHosts share the same IP, allowing a single server to host multiple sites, unlike subdomains which may resolve to different IPs.
- **Challenge**: Non-public subdomains/VHosts (e.g., under `academy.htb`) are not discoverable via public DNS or standard subdomain fuzzing.

## VHost Fuzzing
- **Purpose**: Identify both public and non-public subdomains/VHosts on a known IP by fuzzing the HTTP `Host` header.
- **Method**:
  - Avoid manually updating `/etc/hosts` for each potential subdomain.
  - Use `ffuf` with the `-H` flag to set the `Host` header with the `FUZZ` keyword.
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:<PORT>/ -H "Host: FUZZ.academy.htb"
  ```
- **Behavior**:
  - All requests target the same IP (`academy.htb`), with the `Host` header varied to test potential VHosts.
  - Default response: HTTP 200 OK for all requests, as the server accepts any `Host` header and serves the default site (e.g., `academy.htb`).
  - **Detection**: Valid VHosts return different response sizes, indicating a unique page served for that host.

## Key Insights
- **Response Analysis**: Filter results by response size to identify valid VHosts, as different sizes suggest distinct content.
- **Non-Public VHosts**: Enables discovery of hidden subdomains (e.g., `admin.academy.htb`) not listed in public DNS, critical for local HTB environments.


# Notes on Filtering Results

## Introduction
- Default `ffuf` behavior filters out HTTP 404 (Not Found) responses, retaining codes like 200, 301, etc.
- Issue: VHost fuzzing on `academy.htb` returns many HTTP 200 responses, necessitating additional filtering to identify valid VHosts.

## Filtering Options in Ffuf
- **Command**: `ffuf -h` reveals filtering and matching options:
  - **Matcher Options**:
    - `-mc`: Match HTTP status codes (default: 200, 204, 301, 302, 307, 401, 403).
    - `-ml`: Match response line count.
    - `-mr`: Match response regex.
    - `-ms`: Match response size.
    - `-mw`: Match response word count.
  - **Filter Options**:
    - `-fc`: Filter HTTP status codes.
    - `-fl`: Filter response line count.
    - `-fr`: Filter response regex.
    - `-fs`: Filter response size.
    - `-fw`: Filter response word count.
- **Strategy**: Filtering is preferred over matching when the response size of valid VHosts is unknown, but the size of incorrect responses is known.

## VHost Fuzzing with Filtering
- **Context**: Previous VHost fuzzing showed all responses with HTTP 200 and a consistent response size of 900 bytes for incorrect VHosts.
- **Filter**: Use `-fs 900` to exclude responses with size 900 bytes.
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:<PORT>/ -H "Host: FUZZ.academy.htb" -fs 900
  ```
- **Ffuf Configuration**:
  - Method: GET
  - Wordlist: `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`
  - Header: `Host: FUZZ.academy.htb`
  - Threads: 40
  - Timeout: 10 seconds
  - Matcher: HTTP status codes 200, 204, 301, 302, 307, 401, 403
  - Filter: Response size 900
  - Progress: 4,997 requests (~1,249 req/sec, ~4 seconds)
- **Result**:
  - `admin.academy.htb`: HTTP 200, Size: 0, Words: 1, Lines: 1.

## Verification
- **Update /etc/hosts**:
  - Add `admin.academy.htb` to `/etc/hosts` with the server IP:
    ```bash
    sudo sh -c 'echo "<SERVER_IP> admin.academy.htb" >> /etc/hosts'
    ```
- **Access Check**:
  - Visit `https://admin.academy.htb:<PORT>/`:
    - Returns an empty page, unlike `academy.htb`, confirming a distinct VHost.
  - Visit `https://admin.academy.htb:<PORT>/blog/index.php`:
    - Returns HTTP 404 (Not Found), further confirming a separate VHost with different content.
- **Note**: Ensure the correct port is used, especially if the exercise has been restarted.

## Next Steps
- Perform a recursive scan on `admin.academy.htb` to identify pages and directories:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://admin.academy.htb:<PORT>/FUZZ -recursion -recursion-depth 1 -e .php -v
  ```


# Notes on GET Parameter Fuzzing

## Introduction
- **Context**: Recursive scan on `admin.academy.htb` reveals `http://admin.academy.htb:<PORT>/admin/admin.php`, which displays: "You don't have access to read the flag!"
- **Hypothesis**: Access may require a specific parameter (e.g., a key) passed via GET or POST request to authenticate or unlock content.
- **Objective**: Use `ffuf` to fuzz GET parameters to identify valid ones that grant access.
- **Significance**: Fuzzing may uncover unpublished, less-secure parameters, which are prime targets for web vulnerabilities.

## GET Request Fuzzing
- **GET Parameters**: Passed in the URL after a `?` (e.g., `http://admin.academy.htb:<PORT>/admin/admin.php?param1=key`).
- **Methodology**:
  - Replace the parameter name (e.g., `param1`) with the `FUZZ` keyword.
  - Use a wordlist of common parameter names.
  - Filter out default responses to isolate valid parameters.
- **Wordlist**: `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`.
- **Challenge**: Many responses may return HTTP 200, requiring filtering by response size to identify unique results.
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:<PORT>/admin/admin.php?FUZZ=key -fs <default_response_size>
  ```
- **Notes**:
  - `<default_response_size>` must be determined from initial scans (e.g., size of the "access denied" page).
  - The `key` value is a placeholder; actual fuzzing of parameter values is covered in later sections.

## Key Insights
- **Security Implications**: Discovered parameters may be poorly tested, making them vulnerable to exploitation (e.g., SQL injection, XSS).
- **Next Steps**: If a valid parameter is found, test it for vulnerabilities or proceed to fuzz parameter values to unlock the flag.


# Notes on POST Parameter and Value Fuzzing

## POST Parameter Fuzzing

### Introduction
- **Context**: Continues from GET parameter fuzzing on `http://admin.academy.htb:<PORT>/admin/admin.php`, which indicated restricted access to a flag.
- **Difference from GET**: POST parameters are sent in the HTTP request body, not appended to the URL, requiring specific `ffuf` flags.
- **Objective**: Fuzz POST parameters to identify those accepted by `admin.php`.

### Methodology
- **Ffuf Flags**:
  - `-d`: Specifies POST data with the `FUZZ` keyword for parameter names.
  - `-X POST`: Sets the HTTP method to POST.
  - `-H "Content-Type: application/x-www-form-urlencoded"`: Ensures PHP compatibility for POST data.
- **Wordlist**: `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`.
- **Command**:
  ```bash
  ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:<PORT>/admin/admin.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "FUZZ=key" -fs <default_response_size>
  ```
- **Note**: `<default_response_size>` is the size of the default "access denied" response, used to filter out invalid results.

### Results
- **Hits**:
  - Same parameter as found in GET fuzzing (not specified).
  - New parameter: `id`.
- **Verification**:
  - Test `id` with a POST request using `curl`:
    ```bash
    curl -X POST http://admin.academy.htb:<PORT>/admin/admin.php -d "id=key"
    ```
  - Response: `<div class='center'><p>Invalid id!</p> ...`, indicating `id` is a valid parameter but requires a specific value.

## Value Fuzzing

### Introduction
- **Objective**: Fuzz values for the `id` parameter to find the correct one that grants access to the flag.
- **Challenge**: No pre-made wordlist may match the expected value format, requiring a custom wordlist.

### Custom Wordlist Creation
- **Assumption**: `id` likely accepts a numerical value (e.g., sequential IDs from 1 to 1000).
- **Command**:
  ```bash
  for i in $(seq 1 1000); do echo $i >> ids.txt; done
  ```
- **Output**: Creates `ids.txt` with numbers 1 to 1000:
  ```
  1
  2
  3
  ...
  ```
- **Alternative**: Use existing SecLists wordlists (e.g., for usernames) or script custom formats in Bash/Python if the parameter expects non-numeric values.

### Value Fuzzing Process
- **Methodology**:
  - Place `FUZZ` where the `id` value belongs in the POST data.
  - Use `ids.txt` as the wordlist.
- **Command**:
  ```bash
  ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:<PORT>/admin/admin.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "id=FUZZ" -fs <default_response_size>
  ```
- **Result**: Identifies a valid `id` value (specific status and size redacted).

### Verification
- **Final POST Request**:
  - Use `curl` with the discovered `id` value:
    ```bash
    curl -X POST http://admin.academy.htb:<PORT>/admin/admin.php -d "id=<valid_id>"
    ```
  - Collects the flag from the response.

## Key Insights
- **POST Fuzzing**: Essential for parameters not exposed in URLs, using `-d` and `-X POST` with appropriate headers.
- **Custom Wordlists**: Critical for value fuzzing when parameters expect specific formats (e.g., numeric IDs).
- **Security Note**: Discovered parameters/values may reveal vulnerabilities, warranting further testing (e.g., injection attacks).

