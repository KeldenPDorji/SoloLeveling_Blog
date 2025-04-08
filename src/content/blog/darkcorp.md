---
title: "DarkCorp"
description: "Week 1 Machine: DarkCorp."
pubDate: "April 08 2025"
heroImage: "/DarkCorp.png"
---

# Week 1 Machine: DarkCorp

### Windows · Insane

# Introduction

DarkCorp is an "Insane" difficulty machine on HackTheBox that challenges participants to employ advanced reconnaissance, exploitation, and privilege escalation techniques. This walkthrough provides a step-by-step guide to compromising the DarkCorp machine, offering clear explanations suitable for beginners.

# Reconnaissance

## **1. Initial Connectivity Check**

The target machine's availability was verified using the `ping` command:

![Screenshot From 2025-02-14 14-59-27.png](../Images/darkcorp/Screenshot_From_2025-02-14_14-59-27.png)

A successful response indicates that the target is reachable.

## **2. Web Server Fingerprinting**

Identify the web server and technologies in use with `whatweb`:

This tool provides insights into the server's software, which can be crucial for identifying potential vulnerabilities.

![Screenshot From 2025-02-14 15-22-25.png](../Images/darkcorp/Screenshot_From_2025-02-14_15-22-25.png)

This provided insights into the server's software, which is crucial for identifying potential vulnerabilities.

## **3. Hostname Resolution**

To access services configured with virtual hosts, I updated the /etc/hosts file and pinged again to confirm:

![Screenshot From 2025-02-14 15-26-56.png](../Images/darkcorp/Screenshot_From_2025-02-14_15-26-56.png)

This allowed for proper resolution of the `drip.htb` domain.

![Screenshot From 2025-02-14 15-29-42.png](../Images/darkcorp/Screenshot_From_2025-02-14_15-29-42.png)

## **4. Network Scanning**

An initial `Nmap` scan was conducted to identify open ports and services:

![Screenshot From 2025-02-14 15-34-08.png](../Images/darkcorp/Screenshot_From_2025-02-14_15-34-08.png)

This scan revealed that ports 22 (SSH) and 80 (HTTP) were open.

A comprehensive scan of all ports was also performed:

![Screenshot From 2025-02-14 15-43-55.png](../Images/darkcorp/Screenshot_From_2025-02-14_15-43-55.png)

## 5. Directory Enumeration

The `gobuster` tool was employed to discover hidden directories on the web server:

![Screenshot From 2025-02-15 21-43-02.png](../Images/darkcorp/Screenshot_From_2025-02-15_21-43-02.png)

This enumeration uncovered the following directories:

`/dashboard (Status: 301)
/index.html (Status: 200)`

Subsequently, `gobuster` was run against the `drip.htb` domain:

![Screenshot From 2025-02-14 16-08-21.png](../Images/darkcorp/Screenshot_From_2025-02-14_16-08-21.png)

This revealed additional directories:

`/contact (Status: 302)
/index.html (Status: 200)
/index (Status: 200)
/register (Status: 200)`

![Screenshot From 2025-02-15 21-17-47.png](../Images/darkcorp/Screenshot_From_2025-02-15_21-17-47.png)

After registering with test credentials, the site redirected to `mail.drip.htb/` and became inaccessible.

![Screenshot From 2025-02-15 21-46-56.png](../Images/darkcorp/Screenshot_From_2025-02-15_21-46-56.png)

## **6. Subdomain Discovery**

Based on the pattern of subdomains, the `/etc/hosts` file was further updated to include `mail.drip.htb`:

![Screenshot From 2025-02-16 01-55-12.png](../Images/darkcorp/Screenshot_From_2025-02-16_01-55-12.png)

Accessing `mail.drip.htb` presented a login page, indicating the presence of a mail service.

![Screenshot From 2025-02-16 01-55-35.png](../Images/darkcorp/Screenshot_From_2025-02-16_01-55-35.png)

![Screenshot From 2025-02-16 02-05-45.png](../Images/darkcorp/Screenshot_From_2025-02-16_02-05-45.png)

# Exploitation

## Web Application Analysis

The `/register` page on `drip.htb` was examined, which displayed a user registration form. Attempts to register a new user did not yield any immediate leads.

## Service Enumeration

Given the open ports, the following services were probed:

`HTTP (Port 80):`Standard web service hosting the main site.
`SSH (Port 22):`Secure Shell service, typically used for remote administration.

## Vulnerability Assessment

The following tools and techniques were employed to identify potential vulnerabilities:

**Nginx Version Analysis:** The server was identified as running Nginx 1.22.1. Public vulnerability databases were consulted to check for known exploits against this version.

![Screenshot From 2025-02-15 22-12-04.png](../Images/darkcorp/Screenshot_From_2025-02-15_22-12-04.png)

**WAF Detection:** `wafw00f` was used to detect the presence of a Web Application Firewall:

![Screenshot From 2025-02-16 00-23-48.png](../Images/darkcorp/Screenshot_From_2025-02-16_00-23-48.png)

No significant findings were reported.

**SMB Enumeration:** `smbmap` was utilized to check for accessible SMB shares:

![Screenshot From 2025-02-16 01-03-22.png](../Images/darkcorp/Screenshot_From_2025-02-16_01-03-22.png)

No accessible shares were found.

**SQL Injection Testing:** `sqlmap` was employed to test the `/register` page for SQL injection vulnerabilities:

![Screenshot From 2025-02-16 01-04-04.png](../Images/darkcorp/Screenshot_From_2025-02-16_01-04-04.png)

The tests did not reveal any exploitable SQL injection points.

## Privilege Escalation

Since initial exploitation attempts were unsuccessful, additional enumeration and analysis will be required to discover potential misconfigurations or vulnerabilities that could enable privilege escalation.