---
title: "Linux"
description: "Linux is a family of open-source Unix-like operating systems primarily based on the Linux kernel, a software that manages hardware resources"
pubDate: "May 13 2025"
heroImage: "/linux.jpg"
---

# Linux Daily Essentials

This is your quick-reference guide for thriving in Linux, especially if the terminal is your daily playground. Covering the bash prompt, getting help, Linux distros, system structure, shell basics, and navigation, it’s your practical cheat sheet for staying sharp and efficient. These are real-world tips you’ll lean on constantly.

---

## 1. Owning the Bash Prompt

The bash prompt is your terminal’s welcome mat—showing who you are, where you are, and what power you wield. It’s simple but endlessly tweakable, and a good setup can streamline your daily grind.

- **Default Look**:
  - Format: `<username>@<hostname>:<current_directory>$`
  - Example: `alice@server:~/projects$`
  - `~` = home directory (e.g., `/home/alice`).
  - `$` = regular user; `#` = root (proceed with caution!).
- **Why Tweak It?**:
  - Defaults are okay, but adding time, full paths, or colors makes multitasking or server-hopping clearer.
  - Example: I added time to my prompt to timestamp commands—huge help for tracking bugs.
- **Customize with PS1**:
  - Edit `~/.bashrc` (`nano ~/.bashrc`).
  - PS1 defines the prompt. Basic example:
    ```bash
    PS1='\u@\h:\w\$ '
    ```
    - `\u` = username, `\h` = hostname, `\w` = current directory, `\$` = `$` or `#`.
  - Colorful Example with Time:
    ```bash
    PS1='\[\e[32m\]\t \u@\h:\[\e[33m\]\w\[\e[0m\]\$ '
    ```
    - `\t` = time (HH:MM:SS), `\e[32m` = green, `\e[33m` = yellow path, `\e[0m` = reset.
  - Apply changes: `source ~/.bashrc`.
- **Daily Wins**:
  - **Location Clarity**: `\w` shows full paths (e.g., `/var/log` not just `log`).
  - **Time Stamps**: `\t` logs when commands ran—great for scripts or debugging.
  - **Server Context**: `\h` prevents mix-ups across machines.
- **Handy Codes**:
  - `\d`: Date (e.g., "Wed May 14").
  - `\t`: Time (e.g., "12:03:45").
  - `\u`: Username—comforting as root.
  - `\w`: Full path—cuts down on `pwd`.
- **Fix Tip**: Weird prompt? Reset with: `export PS1='\u@\h:\w\$ '`.

---

## 2. Help Tools for Quick Wins

Linux commands are endless, but you don’t need to memorize them. These help tools are your daily rescue squad—fast answers without constant web searches.

- **Top Tools**:
  1. **`man <command>`**:
     - Full manual. Example: `man mv` details file moving.
     - Daily Use: I check `man tar` to recall `-z` for gzip archives.
  2. **`<command> --help`**:
     - Quick option list. Example: `grep --help` shows `-i` (case-insensitive).
     - Daily Use: Instant refresher when I’m in a rush.
  3. **`<command> -h`**:
     - Brief help for some tools (e.g., `wget -h`). Not universal, but snappy.
- **Practical Uses**:
  - Need hidden files? `ls --help` → `-a`.
  - Downloading with `wget`? `wget -h` → `--no-check-certificate`.
  - `sudo` confusion? `man sudo` explains it all.
- **Extra Helpers**:
  - **`apropos <keyword>`**: Finds commands by keyword. Example: `apropos firewall` → `ufw`.
    - Daily Use: When I’m blanking on a command’s name.
  - [**explainshell.com**](http://explainshell.com/): Breaks down complex commands. Example: `find . -name "*.txt"` → each part explained.
- **Daily Impact**:
  - New commands pop up all the time (`iptables`, `sed`). These tools keep you moving.
  - Tip: `q` exits `man` pages—don’t get stuck!

---

## 3. Linux Distros: Your Daily Ride

Linux distros are like car models—same engine (kernel), different features. Picking the right one for your daily tasks is crucial.

- **What’s a Distro?**:
  - A Linux flavor with unique tools and goals. Examples: Ubuntu (user-friendly), Debian (reliable), Kali (security).
- **Go-To Distros**:
  - **Ubuntu**: Perfect for desktops—simple setup, huge community. Ideal for coding or casual use.
  - **Debian**: Ultra-stable for servers or projects I can’t afford to crash. My choice for consistency.
  - **Kali Linux**: Security pro’s dream—packed with tools like `aircrack-ng`. I use it for pentesting.
- **Debian Spotlight (My Server Pick)**:
  - **Rock-Solid**: Slow, steady updates—set it and forget it.
  - **APT**: `apt update && apt upgrade` keeps things secure effortlessly.
  - **Flexible**: Takes effort to tailor, but I mold it for lightweight setups.
  - Daily Use: My Debian server runs `nginx` for file sharing—up in minutes.
- **Linux vs. Windows**:
  - Free, open, secure. I can inspect code if I want (rarely do).
  - Frequent updates = fewer security worries.
- **Daily Hack**: Dual-boot Ubuntu for general tasks and Kali for security work—best of both worlds.

---

## 4. Linux Layout: Your Daily Map

Understanding Linux’s structure is like knowing your house’s layout—you’ll navigate it daily without thinking.

- **Core Pieces**:
  - **Kernel**: Talks to hardware (CPU, disks). Runs silently in the background.
  - **Shell**: Your command-line pal (usually Bash). Where you issue orders.
  - **File System**: Everything’s a file, starting at `/`.
- **Daily Destinations**:
  - `/home/alice`: My files—scripts, downloads, notes.
  - `/etc`: Configs (e.g., `/etc/fstab` for drives, `/etc/ssh/sshd_config` for SSH).
  - `/var`: Logs (`/var/log/messages`)—debugging starts here.
  - `/tmp`: Temp files for quick experiments; gone after reboot.
  - `/bin`: Core tools (`cat`, `mkdir`).
- **Guiding Principles**:
  - **Files Rule**: Hardware = files (e.g., `/dev/nvme0` = my SSD). Edit text, control the system.
  - **Small Tools Win**: Combine `ls`, `grep`, `cut` for big tasks (e.g., `ls | grep ".log"`).
  - **Shell > GUI**: `cd /etc && nano hosts` is quicker than clicking.
- **Daily Routine**:
  - Check location: `pwd` → `/home/alice/code`.
  - List files: `ls -la` (includes `.gitignore`).
  - Tweak configs: `sudo nano /etc/nginx/nginx.conf`.
- **Fun Fact**: Linux evolved from Unix (1970s) to Linus Torvalds’ kernel (1991). It’s proven and trustworthy.

---

## 5. Shell: Your Daily Power Tool

The shell is your command-line superpower—text-driven but lightning-fast once you get the hang of it.

- **Shell 101**:
  - A program (usually Bash) that runs your commands. Example: `uname -r` → kernel version.
- **Terminal vs. Shell**:
  - Terminal = the app (e.g., Alacritty).
  - Shell = the brains (Bash, Zsh).
  - Analogy: Terminal’s the canvas; shell’s the painter.
- **Why It Rocks**:
  - Speed: `mv file.txt backup/` beats dragging files.
  - Scripts: Automate tasks. Example script:
    ```bash
    #!/bin/bash
    apt update && apt upgrade -y
    ```
- **Terminal Tricks**:
  - Tmux splits your screen—monitor logs while editing files.
    - Daily Use: `tmux split-window -v` → top/bottom panes.
- **Shell Alternatives**:
  - Bash is standard, but Zsh (cool prompts) or Fish (smart suggestions) are fun to explore.
- **Daily Commands**:
  - `cd /etc`: Jump to configs.
  - `cat /var/log/syslog | grep error`: Spot issues.
  - `sudo systemctl reload apache2`: Refresh my web server.

---

## 6. Navigating Like a Boss

Moving through Linux’s filesystem is a core daily skill—whether jumping directories or inspecting files, these commands are your lifeline.

- **Where Am I?**:
  - **`pwd`**: Shows current path. Example: `/home/alice`.
    - Daily Use: Run it when I’m deep in folders and disoriented.
- **What’s Around?**:
  - **`ls`**: Lists files. Example: `code docs images`.
    - Quick and dirty—perfect for a glance.
  - **`ls -l`**: Detailed view—permissions, size, date. Example:
    ```
    -rw-r--r-- 1 alice users 1234 May 14 12:00 notes.txt
    ```
    - Daily Use: Check file details or ownership.
  - **`ls -la`**: Includes hidden files (e.g., `.bashrc`).
    - Tip: Hidden files hold secrets—`.profile` tweaks your login.
  - **`ls /path/`**: Check distant dirs. Example: `ls /usr/local`.
    - Daily Use: Scope out `/var` or `/etc` without moving.
- **Getting Around**:
  - **`cd /path/`**: Switch directories. Example: `cd /var/www`.
    - Daily Use: Hop to work dirs (`cd ~/dev`) or system spots (`cd /etc`).
  - **`cd -`**: Return to previous dir.
    - Saves me when flipping between `/home` and `/opt`.
  - **`cd ..`**: Go up one level. Example: `/var/www` → `/var`.
    - Daily Use: Escape nested folders fast.
  - **Dots Explained**:
    - `.` = here (e.g., `ls .`).
    - `..` = up (e.g., `cd ..`).
- **Auto-Complete**:
  - `[TAB][TAB]` after partial input. Example: `cd /u[TAB][TAB]` → `usr/`.
  - Refine: `cd /us[TAB]` → `usr/`.
  - Daily Use: Speeds up long paths like `/var/lib/docker`.
- **Clear the Deck**:
  - **`clear`**: Resets terminal screen.
    - Daily Use: Clean up after messy logs.
  - Shortcut: `[CTRL + L]`—same deal, faster.
- **Command History**:
  - **Up/Down Arrows**: Reuse recent commands.
  - **`[CTRL + R]`**: Search past commands. Type “cd”, hit enter to rerun.
  - Daily Use: Rerun `ls -la` or old `find` commands effortlessly.
- **Why It’s Essential**:
  - Speed: `cd`, `ls`, `[TAB]` make navigation instant.
  - Recovery: History or `cd -` bails you out when lost.

--- 

## 7. Tracking Down Files and Folders

The “Find Files and Directories” section (pages 1-3) is your guide to pinpointing files, configs, or tools on Linux. Tools like `which`, `find`, and `locate` are my daily staples for quick searches.

- **`which`**:
  - Reveals a program’s location. Example: `which ruby` → `/usr/bin/ruby`.
  - No output? It’s not installed.
  - Daily Use: I run `which wget` to confirm tools before scripting.
- **`find`**:
  - Powerful search with filters. Syntax: `find <path> <options>`.
  - Example: `find / -type f -name "*.log" -user alice -size +50k -newermt 2025-01-01`.
    - Breakdown:
      - `/`: Search entire system.
      - `type f`: Files only.
      - `name "*.log"`: Log files.
      - `user alice`: Owned by alice.
      - `size +50k`: Over 50KB.
      - `newermt 2025-01-01`: Modified after Jan 1, 2025.
    - Output: Paths like `/var/log/app.log`.
  - Daily Use: I search configs (`find /etc -name "*.conf"`) or recent files (`find ~ -newermt 2025-05-01`).
  - Tip: `2>/dev/null` silences “permission denied” errors.
- **`locate`**:
  - Speedy database search. Example: `locate *.conf` → `/etc/nginx.conf`, etc.
  - Refresh DB: `sudo updatedb` for current results.
  - Daily Use: Fast file lookups when I don’t need `find`’s precision.
- **Which vs. Find vs. Locate**:
  - `which`: Locates executables (e.g., `which bash`).
  - `find`: Detailed, slow, customizable.
  - `locate`: Quick, broad, needs updated DB.
- **Daily Routine**:
  - Tool check: `which nmap`.
  - Log hunt: `find /var/log -name "*.log"`.
  - Config sweep: `locate *.conf`.
- **Practice**: Run `which curl`, `find / -name "*curl*" 2>/dev/null`, and `locate curl`—compare results.

---

## 8. Organizing Files and Directories

The “Working with Files and Directories” section (pages 1-6) equips you to create, move, and tidy up. These commands are my daily go-tos for keeping systems neat.

- **Creating**:
  - **`touch <file>`**: Makes empty files. Example: `touch notes.txt`.
    - Daily Use: Create placeholders or update timestamps (`touch debug.log`).
  - **`mkdir <dir>`**: Creates a directory. Example: `mkdir Archives`.
  - **`mkdir -p <path>`**: Builds nested directories. Example: `mkdir -p Archives/data/user/docs`.
    - Daily Use: Set up project structures in one go.
- **Viewing Structure**:
  - **`tree`**: Displays directory tree. Example:
    ```
    .
    ├── notes.txt
    └── Archives
        └── data
            └── user
                └── docs
    ```
    - Daily Use: Visualize folders before reorganizing.
- **Moving/Renaming**:
  - **`mv <source> <dest>`**: Moves or renames.
    - Rename: `mv notes.txt memo.txt`.
    - Move: `mv memo.txt Archives/`.
  - Daily Use: Rename backups (`mv backup.tar backup_2025.tar`) or relocate files (`mv *.jpg images/`).
- **Copying**:
  - **`cp <source> <dest>`**: Copies files. Example: `cp Archives/readme.md Archives/data/`.
  - Daily Use: Duplicate configs for edits (`cp nginx.conf nginx.conf.test`).
- **Deleting**:
  - Use `rm <file>` for files, `rm -r <dir>` for directories.
  - Daily Use: Clear clutter (`rm temp.txt`, `rm -r old_data/`).
  - Safety: `rm -i` prompts before deleting—avoids oops moments.
- **Daily Flow**:
  - Start project: `mkdir -p code/src && touch code/plan.txt`.
  - Tidy: `mv *.bak backups/ && tree`.
  - Backup: `cp settings.conf settings.conf.bak`.
- **Tip**: Combine commands: `mkdir logs && mv *.log logs/`—quick and clean.

---

## 9. Gathering System Info

The “System Information” section (pages 1-5) is your toolkit for scoping out a Linux system. These commands are my daily essentials for diagnostics or security checks.

- **Identity and Location**:
  - **`whoami`**: Shows current user. Example: `alice`.
  - **`id`**: Lists user/group IDs. Example: `uid=1000(alice) groups=1000,4(adm),20(sudo)`.
    - Daily Use: Verify access—`sudo` group means elevated rights.
  - **`hostname`**: System name. Example: `devbox`.
  - **`pwd`**: Current directory (e.g., `/home/alice`).
- **System Details**:
  - **`uname -a`**: Full system info. Example: `Linux devbox 5.15.0-73-generic ... x86_64`.
    - Includes kernel, hostname, architecture.
  - **`uname -r`**: Kernel version. Example: `5.15.0-73-generic`.
    - Daily Use: Check for vulnerabilities (e.g., search “5.15.0-73 exploit”).
- **Network and Processes**:
  - **`ifconfig`**: Classic network details (IP, MAC).
  - **`ip a`**: Modern network view. Example: `eth0: 10.0.0.5`.
  - **`netstat`**: Ports and connections.
  - **`ss`**: Faster port info.
  - **`ps`**: Processes. Example: `ps aux` shows all.
  - Daily Use: `ip a` for IPs, `ps aux | grep apache2` for server status.
- **Hardware and Users**:
  - **`lsblk`**: Disk layout (e.g., `sdb`).
  - **`lsusb`**: USB devices.
  - **`lspci`**: PCI devices (e.g., network card).
  - **`who`**: Active users.
  - **`env`**: Environment variables (e.g., `PATH`).
  - Daily Use: `lsblk` for storage, `who` to check for others.
- **Daily Recon**:
  - New system? `whoami; id; uname -r; ip a`.
  - Issues? `ps aux` + `ss -tulnp` (open ports).
  - Curious? `man <command>` (e.g., `man ss`).

---

## 10. Editing Files with Confidence

The “Editing Files” section (pages 1-5) covers `nano` and `vim` for tweaking files. These are my daily tools for quick fixes or precise edits.

- **`nano`**:
  - Simple editor. Example: `nano config.txt`.
  - Use: Edit, `[CTRL + O]` to save, `[CTRL + X]` to exit.
  - Search: `[CTRL + W]`, enter “error”, `[ENTER]` to find.
  - Daily Use: Adjust configs (`nano /etc/fstab`).
- **Nano Shortcuts**:
  - Save: `[CTRL + O]`, `[ENTER]`.
  - Exit: `[CTRL + X]`.
  - Next match: `[CTRL + W]`, `[ENTER]`.
  - Daily Use: Draft scripts (`nano run.sh`).
- **Viewing**:
  - **`cat <file>`**: Shows contents. Example: `cat config.txt`.
  - Daily Use: Review logs (`cat /var/log/auth.log`).
- **Key Files**:
  - `/etc/passwd`: User accounts (e.g., `alice:x:1000:1000`).
  - `/etc/shadow`: Password hashes (root required).
  - Daily Use: `cat /etc/passwd` for user enumeration.
- **`vim`**:
  - Advanced editor. Example: `vim script.py`.
  - Modes:
    - Normal: Commands (default).
    - Insert: Edit (`i Ascendancyi` to start).
    - Visual: Select text (`v`).
    - Command: Run commands (`:`), e.g., `:wq` to save/quit.
  - Quit: `:q` or `:q!` (force).
  - Daily Use: Edit complex files (`vim app.conf`).
- **VimTutor**:
  - Learn via `vimtutor` (~30 mins).
  - Daily Use: Master navigation (`hjkl`).
- **Daily Choice**:
  - `nano`: Quick tweaks (e.g., `/etc/hosts`).
  - `vim`: Detailed work (e.g., code edits).
  - Verify: `cat` to check edits.

---

## 11. User Management: Running the Team

User management secures and organizes accounts—daily admin work. From “User Management” (pages 1-2).

- **Why It’s Key**: Ensures proper access—think adding a new dev, Sarah.
- **Root vs. Regular**:
  - `cat /etc/shadow` → “Permission denied” (regular).
  - `sudo cat /etc/shadow` → Hashes visible (root).
  - Daily Use: Audit `/etc/shadow` with `sudo`.
- **Commands**:
  - `sudo <cmd>`: Run as another (usually root). Ex: `sudo id` → `root`.
  - `su`: Switch user. Ex: `su -` → root shell.
  - `useradd <name>`: Add user. Ex: `sudo useradd -m sarah`.
  - `userdel <name>`: Remove user. Ex: `sudo userdel sarah`.
  - `usermod`: Modify user. Ex: `sudo usermod -aG coders sarah`.
  - `addgroup <name>`: Create group. Ex: `sudo addgroup coders`.
  - `delgroup <name>`: Delete group. Ex: `sudo delgroup coders`.
  - `passwd <name>`: Set password. Ex: `sudo passwd sarah`.
- **Daily Flow**:
  - Add user: `sudo useradd -m sarah && sudo passwd sarah && sudo usermod -aG coders sarah`.
  - Remove: `sudo userdel sarah && sudo delgroup oldcoders`.
- **Tip**: Test in a VM—break, rebuild, learn.

---

## 12. Permissions: Securing Access

Permissions control file access—your security gatekeeper. From “Permission Management” (pages 1-6).

- **Fundamentals**:
  - Files/dirs have owners and groups.
  - Ex: `ls -l code` → `-rw-r--r-- 1 alice coders`.
  - Permissions: Read (`r`=4), Write (`w`=2), Execute (`x`=1).
  - Octal: `644` = `rw-r--r--` (owner: 6, group: 4, others: 4).
- **Directory Traversal**:
  - Need `x` to enter dir. No `x`? “Permission denied.”
  - Ex: `ls -ld projects/` → fails without `x`.
- **Ownership**:
  - `chown <user>:<group> <file>`: Change owner.
  - Ex: `sudo chown root:root script.sh` → `ls -l` shows `root root`.
- **SUID/SGID**:
  - `s` = run as owner/group. Ex: `rwsr-xr-x` (SUID).
  - Danger: `sudo chmod u+s passwd` → potential root shell (see GTFObins).
  - Daily Use: Find SUIDs with `find / -perm -u=s`.
- **Sticky Bit**:
  - `t` = only owner/root deletes in shared dir.
  - Ex: `drwxrwxrwt` (lowercase `t`=with `x`), `drwxrwxrwT` (uppercase=no `x`).
  - Daily Use: `chmod +t shared` for collaboration.
- **Daily Routine**:
  - Lock file: `sudo chown root:root file && chmod 600 file`.
  - Shared dir: `chmod 1777 tmp`.

---

## 13. Regular Expressions: Pattern Mastery

RegEx is my text-filtering ace—perfect for `grep` or `sed`. From “Regular Expressions” (pages 1-2).

- **Why It Matters**: Spots patterns in logs or configs fast.
- **Syntax**:
  - `()`: Groups. Ex: `(log|error)` = “log” or “error”.
  - `[]`: Characters. Ex: `[0-9]` = any digit.
  - `{}`: Repeats. Ex: `b{3}` = “bbb”.
  - `|`: OR. Ex: `grep -E "(log|error)" log.txt`.
  - `.*`: Sequence. Ex: `grep -E "(log.*error)" log.txt`.
- **Examples**:
  - OR: `grep -E "(log|error)" log.txt` → lines with either.
  - AND: `grep -E "(log.*error)" log.txt` → “log” then “error”.
  - Dual grep: `grep -E "log" log.txt | grep -E "error"`.
- **Practice (on `/etc/ssh/sshd_config`)**:
  1. No comments: `grep -v "^#"`.
  2. Starts “Allow”: `grep "^Allow"`.
  3. Ends “Password”: `grep "Password$"`.
  4. Contains “Port”: `grep "Port"`.
  5. Starts “Permit” + “yes”: `grep "^Permit.*yes"`.
  6. Ends “no”: `grep "no$"`.
- **Daily Use**: Find settings—`grep -E "Listen.*80" nginx.conf`.

---

## 14. Filtering Data: Cutting Through Clutter

Filtering tools like `grep`, `cut`, and `awk` tame data chaos. From “Filter Contents” (pages 1-8).

- **Pagers**:
  - `more`: Scroll down, `[Q]` quits, output lingers.
  - `less`: Scroll freely, `[Q]` quits, screen clears.
  - Ex: `cat /etc/group | less`.
- **Head/Tail**:
  - `head`: First 10 lines. Ex: `head /etc/group`.
  - `tail`: Last 10. Ex: `tail /etc/group`.
  - Custom: `tail -n 3` (last 3).
- **Sort**:
  - Alphabetize: `cat /etc/group | sort`.
- **Grep**:
  - Filter: `grep "/bin/sh" /etc/passwd`.
  - Exclude: `grep -v "false\\|nologin" /etc/passwd`.
- **Cut**:
  - Extract: `cut -d':' -f1 /etc/passwd` → usernames.
- **Tr**:
  - Swap: `tr ':' '-' < /etc/passwd` → colons to dashes.
- **Column**:
  - Format: `cat /etc/passwd | tr ':' ' ' | column -t`.
- **Awk**:
  - Fields: `awk '{print $1 " " $NF}' /etc/passwd` → username, shell.
- **Sed**:
  - Replace: `sed 's/root/admin/g' /etc/passwd` → “root” to “admin”.
- **Wc**:
  - Count: `grep "/bin/sh" /etc/passwd | wc -l` → sh users.
- **Daily Combo**: `cat /etc/passwd | grep -v "false" | cut -d':' -f1 | sort | wc -l`.

---

## 15. File and Directory Search: Finding Gold

Locating files—configs, logs, tools—is a daily must. From “Find Files and Directories” (pages 1-3).

- **`which`**:
  - Tool’s path. Ex: `which gcc` → `/usr/bin/gcc`.
  - Daily Use: `which dig`—is it installed?
- **`find`**:
  - Custom search. Ex: `find / -type d -name "*backup*" -group users`.
  - Options: `type f` (files), `newermt "2025-03-01"`, `exec ls -l {} \\;`.
  - Silence errors: `2>/dev/null`.
- **`locate`**:
  - Quick DB lookup. Ex: `locate *.log`.
  - Update: `sudo updatedb`.
- **Daily Flow**:
  - Verify tool: `which traceroute`.
  - Find configs: `find /etc -name "*.conf" 2>/dev/null`.
  - Fast check: `locate passwd`.
- **Practice**: Try `which bash`, `find / -name "*bash*" 2>/dev/null`, `locate bash`.

---

## 16. Redirections: Controlling Flow

Redirections handle input/output like magic—STDIN, STDOUT, STDERR. From “File Descriptors and Redirections” (pages 1-6).

- **Descriptors**:
  - `0`: STDIN (input).
  - `1`: STDOUT (output).
  - `2`: STDERR (errors).
- **Examples**:
  - STDIN: `cat` → type “Linux”, see “Linux”.
  - STDOUT/STDERR: `find / -name passwd` → files (1), errors (2).
- **Redirect**:
  - Drop errors: `find / -name passwd 2>/dev/null`.
  - Save STDOUT: `> output.txt`.
  - Split: `2> errors.txt 1> output.txt`.
  - Append: `>> output.txt`.
  - Stream STDIN: `cat << EOF > data.txt` → type, end with “EOF”.
- **Pipes**:
  - Chain: `find /etc -name "*.conf" 2>/dev/null | grep nginx | wc -l`.
- **Daily Use**:
  - Clean output: `ls dir 2>/dev/null > files.txt`.
  - Log data: `grep "fail" log.txt >> fails.txt`.

---
