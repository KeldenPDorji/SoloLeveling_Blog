---
title: "Titanic"
description: "Week 2 Machine: Titanic."
pubDate: "April 08 2025"
heroImage: "/Titanic.png"
---

# Week 2 Machine: Titanic

# Introduction

Titanic is an "Easy" difficulty machine on HackTheBox that offers participants an opportunity to practice web enumeration, path traversal exploitation, and password cracking techniques. This walkthrough provides a structured approach to compromising the Titanic machine, ensuring clarity for beginners.

# Reconnaissance

## Initial Connectivity Check

The target machine's availability was confirmed using the `ping` command:

![Screenshot From 2025-02-17 14-56-56.png](../Images/titanic/Screenshot_From_2025-02-17_14-56-56.png)

A successful response indicated that the target was reachable.

## Hostname Resolution

To facilitate access to services configured with virtual hosts, the `/etc/hosts` file was updated:

![Screenshot From 2025-02-22 21-34-01.png](../Images/titanic/Screenshot_From_2025-02-22_21-34-01.png)

This allowed proper resolution of the `titanic.htb` domain.

![Screenshot From 2025-02-22 21-36-19.png](../Images/titanic/Screenshot_From_2025-02-22_21-36-19.png)

## Subdomain Enumeration

Utilizing `ffuf`, a subdomain enumeration was performed to discover additional subdomains:

![Screenshot From 2025-02-22 22-55-22.png](../Images/titanic/Screenshot_From_2025-02-22_22-55-22.png)

This scan identified the `dev` subdomain.

## Directory Enumeration

Using `gobuster`, directory enumeration was conducted on the main domain:

![Screenshot From 2025-02-22 23-13-27.png](../Images/titanic/Screenshot_From_2025-02-22_23-13-27.png)

The following directories were discovered:

`/book
/download
/server-status`

## Web Application Analysis

Accessing `titanic.htb/` revealed a web application. The `Wappalyzer` browser extension identified the application as utilizing the Flask framework, indicating a Python-based backend.

![Screenshot From 2025-02-22 21-42-41.png](../Images/titanic/Screenshot_From_2025-02-22_21-42-41.png)

![Screenshot From 2025-02-22 21-43-08.png](../Images/titanic/Screenshot_From_2025-02-22_21-43-08.png)

## Service Enumeration

A targeted Nmap scan was performed to identify open services:

![Screenshot From 2025-02-22 21-53-49.png](../Images/titanic/Screenshot_From_2025-02-22_21-53-49.png)

The scan results indicated that ports 22 (SSH) and 80 (HTTP) were open.

# Exploitation

## Web Functionality Testing

Interacting with the /book directory presented a booking form. Using Burp Suite's intercepting proxy, the form was submitted with arbitrary data, capturing the request for analysis. The server's response included a download?tickets= parameter.

![Screenshot From 2025-02-22 22-09-47.png](../Images/titanic/Screenshot_From_2025-02-22_22-09-47.png)

![Screenshot From 2025-02-22 22-10-06.png](../Images/titanic/Screenshot_From_2025-02-22_22-10-06.png)

![Screenshot From 2025-02-22 22-11-00.png](../Images/titanic/Screenshot_From_2025-02-22_22-11-00.png)

![Screenshot From 2025-02-22 22-15-32.png](../Images/titanic/Screenshot_From_2025-02-22_22-15-32.png)

![Screenshot From 2025-02-22 22-15-45.png](../Images/titanic/Screenshot_From_2025-02-22_22-15-45.png)

![Screenshot From 2025-02-22 22-16-56.png](../Images/titanic/Screenshot_From_2025-02-22_22-16-56.png)

## Path Traversal Vulnerability

Testing for path traversal, the following URL was crafted:

![Screenshot From 2025-02-22 22-17-56.png](../Images/titanic/Screenshot_From_2025-02-22_22-17-56.png)

![Screenshot From 2025-02-22 22-18-40.png](../Images/titanic/Screenshot_From_2025-02-22_22-18-40.png)

![Screenshot From 2025-02-22 22-19-20.png](../Images/titanic/Screenshot_From_2025-02-22_22-19-20.png)

This payload successfully retrieved the `/etc/passwd` file, confirming a path traversal vulnerability.

![Screenshot From 2025-02-22 23-03-13.png](../Images/titanic/Screenshot_From_2025-02-22_23-03-13.png)

## Sensitive Data Access

Within the `/etc/passwd` file, an entry for developer was found, indicating a user account. Attempting to access the user's home directory, the following URL was used:

![Screenshot From 2025-02-22 23-09-28.png](../Images/titanic/Screenshot_From_2025-02-22_23-09-28.png)

![Screenshot From 2025-02-22 23-10-51.png](../Images/titanic/Screenshot_From_2025-02-22_23-10-51.png)

![Screenshot From 2025-02-22 23-11-16.png](../Images/titanic/Screenshot_From_2025-02-22_23-11-16.png)

![Screenshot From 2025-02-22 23-11-57.png](../Images/titanic/Screenshot_From_2025-02-22_23-11-57.png)

![Screenshot From 2025-02-22 23-13-04.png](../Images/titanic/Screenshot_From_2025-02-22_23-13-04.png)

This successfully retrieved the `user.txt` file, containing the user flag: `a79492d2a5c8e005bfecffbb184d5188`.

# Privilege Escalation

## Subdomain Exploration

Recognizing the previously discovered `dev` subdomain, the /etc/hosts file was updated:

![Screenshot From 2025-02-22 23-24-56.png](../Images/titanic/Screenshot_From_2025-02-22_23-24-56.png)

![Screenshot From 2025-02-22 23-25-18.png](../Images/titanic/Screenshot_From_2025-02-22_23-25-18.png)

Accessing `dev.titanic.htb/` revealed a development site with a navigation bar leading to hidden repositories, including `developer/flask-app/app.py.`

![Screenshot From 2025-02-22 23-26-51.png](../Images/titanic/Screenshot_From_2025-02-22_23-26-51.png)

## Source Code Analysis

Reviewing `app.py` provided insights into the application's structure and potential vulnerabilities.

![Screenshot From 2025-02-22 23-27-16.png](../Images/titanic/Screenshot_From_2025-02-22_23-27-16.png)

![Screenshot From 2025-02-22 23-27-59.png](../Images/titanic/Screenshot_From_2025-02-22_23-27-59.png)

![Screenshot From 2025-02-22 23-28-44.png](../Images/titanic/Screenshot_From_2025-02-22_23-28-44.png)

![Screenshot From 2025-02-22 23-28-55.png](../Images/titanic/Screenshot_From_2025-02-22_23-28-55.png)

## Database Extraction

Utilizing the path traversal vulnerability, the Gitea configuration file was accessed:

![Screenshot From 2025-02-22 23-29-48.png](../Images/titanic/Screenshot_From_2025-02-22_23-29-48.png)

![Screenshot From 2025-02-22 23-30-16.png](../Images/titanic/Screenshot_From_2025-02-22_23-30-16.png)

This file revealed the database path: `/data/gitea/gitea.db.` The database was then downloaded:

![Screenshot From 2025-02-22 23-32-57.png](../Images/titanic/Screenshot_From_2025-02-22_23-32-57.png)

## Credential Extraction and Cracking

Analyzing the `SQLite` database, user credentials were extracted:

![Screenshot From 2025-02-22 23-34-05.png](../Images/titanic/Screenshot_From_2025-02-22_23-34-05.png)

The resulting hashes were cracked using `hashcat` with the `rockyou.txt` wordlist:

![Screenshot From 2025-02-22 23-40-35.png](../Images/titanic/Screenshot_From_2025-02-22_23-40-35.png)

This process successfully revealed the password for the developer account.

![Screenshot From 2025-02-22 23-41-13.png](../Images/titanic/Screenshot_From_2025-02-22_23-41-13.png)

## SSH Access

With the cracked credentials, SSH access was established:

![Screenshot From 2025-02-22 23-42-37.png](../Images/titanic/Screenshot_From_2025-02-22_23-42-37.png)

Upon successful login, the `user.txt` flag was confirmed.

![Screenshot From 2025-02-22 23-43-55.png](../Images/titanic/Screenshot_From_2025-02-22_23-43-55.png)

### Identifying Writable Directories

Begin by searching for directories with write permissions:

![Screenshot From 2025-02-22 23-45-15.png](../Images/titanic/Screenshot_From_2025-02-22_23-45-15.png)

![Screenshot From 2025-02-22 23-45-53.png](../Images/titanic/Screenshot_From_2025-02-22_23-45-53.png)

### Analyzing the /opt/scripts/identify_images.sh Script

Within the `/opt/scripts/` directory, a script named identify_images.sh is present:

![Screenshot From 2025-02-22 23-56-25.png](../Images/titanic/Screenshot_From_2025-02-22_23-56-25.png)

This script changes the directory to /opt/app/static/assets/images, truncates the metadata.log file, and uses find in combination with xargs to execute ImageMagick's identify command on all .jpg files, appending the output to metadata.log.

![Screenshot From 2025-02-22 23-59-10.png](../Images/titanic/Screenshot_From_2025-02-22_23-59-10.png)

![Screenshot From 2025-02-23 00-02-33.png](../Images/titanic/Screenshot_From_2025-02-23_00-02-33.png)

### Leveraging the Writable `/opt/app/static/assets/images` Directory

The /opt/app/static/assets/images directory is writable by the developer user:

`ls -la /opt/app/static/assets/images`

Output:

drwxrwx--- 2 root developer   4096 Feb  3 17:13 .
drwxr-x--- 3 root developer   4096 Feb  7 10:37 ..
-rw-r----- 1 root developer 291864 Feb  3 17:13 entertainment.jpg
-rw-r----- 1 root developer 280854 Feb  3 17:13 exquisite-dining.jpg
-rw-r----- 1 root developer 209762 Feb  3 17:13 favicon.ico
-rw-r----- 1 root developer 232842 Feb  3 17:13 home.jpg
-rw-r----- 1 root developer 280817 Feb  3 17:13 luxury-cabins.jpg
-rw-r----- 1 root developer    442 Feb 22 18:07 metadata.log
-rwxr-xr-- 1 root root          33 Feb 22 17:45 root.txt

Given the write permissions, it's possible to exploit the `identify_images.sh` script by introducing a `malicious .jpg file` that, when processed, executes arbitrary commands.

### Crafting a Malicious Image

ImageMagick's `identify` command can be exploited through a technique known as "ImageTragick." Create a malicious image file that, when processed, will execute a command to copy the `root.txt` flag to a location accessible by the `developer` user:

![Screenshot From 2025-02-23 00-04-23.png](../Images/titanic/Screenshot_From_2025-02-23_00-04-23.png)

### Retrieving the Root Flag

After execution, verify the presence of the `root.txt` file:

![Screenshot From 2025-02-23 00-08-16.png](../Images/titanic/Screenshot_From_2025-02-23_00-08-16.png)