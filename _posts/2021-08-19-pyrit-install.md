---
layout: post
title: Pyrit install Kali linux - 2021
tags: [WiFi, Linux]
description: Pyrit install Kali linux - 2021
---

![logo](/assets/imgs/pyrit_error/logo.png)

Recently I was seeing in the forums that many had problems in the installation process of this tool.

Today I will explain how to solve several of these common errors that can occur

It is worth mentioning that I will be using the Kali Linux 2021.2 Operating System but this will also work in previous versions.

```
❯ cat /etc/os-release
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
ID=kali
VERSION="2021.2"
VERSION_ID="2021.2"
VERSION_CODENAME="kali-rolling"
ID_LIKE=debian
ANSI_COLOR="1;31"
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
```

Kali Linux comes installed by default with these two versions of python.

```
❯ python3 -V
Python 3.9.2

❯ python -V
Python 2.7.18

```

## Pyrit repository
First we will clone the Pyrit project.

Link: [https://github.com/JPaulMora/Pyrit](https://github.com/JPaulMora/Pyrit)

```
❯ git clone https://github.com/JPaulMora/Pyrit
```

![github](/assets/imgs/pyrit_error/github.png)

-----

## Installation from the wiki

Link: [https://github.com/JPaulMora/Pyrit/wiki](https://github.com/JPaulMora/Pyrit/wiki)

Then the only thing I do is follow the guide that the page itself shows us.

![wiki](/assets/imgs/pyrit_error/wiki.png)

I install ```psycopg2``` and ```scapy``` but these packages are already installed by default, so for now everything is fine.

```
❯ sudo pip install psycopg2
[sudo] password for user:
Requirement already satisfied: psycopg2 in /usr/lib/python3/dist-packages (2.8.6)
```

```
❯ sudo pip install scapy
Requirement already satisfied: scapy in /usr/lib/python3/dist-packages (2.4.4)
```

We continue with the guide.

```
❯ cd Pyrit
❯ python setup.py clean
running clean

```

And this is where the problems of the damn pyrit begin, which has caused so many headaches for many.

```
❯ python setup.py build
running build
running build_py
creating build
creating build/lib.linux-x86_64-2.7
copying pyrit_cli.py -> build/lib.linux-x86_64-2.7
creating build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/__init__.py -> build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/cpyrit.py -> build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/util.py -> build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/pckttools.py -> build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/config.py -> build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/network.py -> build/lib.linux-x86_64-2.7/cpyrit
copying cpyrit/storage.py -> build/lib.linux-x86_64-2.7/cpyrit
running build_ext
building 'cpyrit._cpyrit_cpu' extension
creating build/temp.linux-x86_64-2.7
creating build/temp.linux-x86_64-2.7/cpyrit
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-PsnjKG/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu.c -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o -Wall -fno-strict-aliasing -DVERSION="0.5.1" -maes -mpclmul
cpyrit/_cpyrit_cpu.c:32:10: fatal error: Python.h: No existe el fichero o el directorio
   32 | #include <Python.h>
      |          ^~~~~~~~~~
compilation terminated.
Failed to build; Compiling without AES-NI
building 'cpyrit._cpyrit_cpu' extension
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-PsnjKG/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu.c -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o -Wall -fno-strict-aliasing -DVERSION="0.5.1"
cpyrit/_cpyrit_cpu.c:32:10: fatal error: Python.h: No existe el fichero o el directorio
   32 | #include <Python.h>
      |          ^~~~~~~~~~
compilation terminated.
error: command 'x86_64-linux-gnu-gcc' failed with exit status 1
```

So looking for this problem in the pyrit issues I see that many others had the same error.

![failedx86](/assets/imgs/pyrit_error/failedx86.png)

This is because we have not yet been able to install the dependencies for this tool. This is solved by applying the following command.

Link issue: [https://github.com/JPaulMora/Pyrit/issues/594](https://github.com/JPaulMora/Pyrit/issues/594)

```
❯ sudo apt-get install python3 python-dev python3-dev build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev
```

Let's build pyrit again

```
❯ python setup.py build
running build
running build_py
running build_ext
building 'cpyrit._cpyrit_cpu' extension
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu.c -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o -Wall -fno-strict-aliasing -DVERSION="0.5.1" -maes -mpclmul
cpyrit/_cpyrit_cpu.c:40:10: fatal error: pcap.h: No existe el fichero o el directorio
   40 | #include <pcap.h>
      |          ^~~~~~~~
compilation terminated.
Failed to build; Compiling without AES-NI
building 'cpyrit._cpyrit_cpu' extension
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu.c -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o -Wall -fno-strict-aliasing -DVERSION="0.5.1"
cpyrit/_cpyrit_cpu.c:40:10: fatal error: pcap.h: No existe el fichero o el directorio
   40 | #include <pcap.h>
      |          ^~~~~~~~
compilation terminated.
error: command 'x86_64-linux-gnu-gcc' failed with exit status 1
```

Sparkly! What do you think :(

## Libpcap dependency

We go back to the [issue](https://github.com/JPaulMora/Pyrit/issues/594) and find a user who has the same problems.

![libpcap](/assets/imgs/pyrit_error/libcap.png)

The error arises because we have not yet fully complied with the dependencies.

We execute the following command.

❯ sudo apt-get install libpcap-dev                                                                    
Leyendo lista de paquetes... Hecho
Creando árbol de dependencias... Hecho                                                                
Leyendo la información de estado... Hecho                                                             
Los paquetes indicados a continuación se instalaron de forma automática y ya no son necesarios.       
  libdee-1.0-4 libdiodon0 libpeas-1.0-0 libpeas-common libxapian30 libzeitgeist-2.0-0 zeitgeist-core
Utilice «sudo apt autoremove» para eliminarlos.
Se instalarán los siguientes paquetes adicionales:
  libdbus-1-dev libpcap0.8-dev                                                                 
Se instalarán los siguientes paquetes NUEVOS:                                                  
  libdbus-1-dev libpcap-dev libpcap0.8-dev
0 actualizados, 3 nuevos se instalarán, 0 para eliminar y 284 no actualizados.
Se necesita descargar 568 kB de archivos.
Se utilizarán 1.926 kB de espacio de disco adicional después de esta operación.
¿Desea continuar? [S/n] S
Des:1 http://kali.download/kali kali-rolling/main amd64 libdbus-1-dev amd64 1.12.20-2 [256 kB]
Des:2 http://kali.download/kali kali-rolling/main amd64 libpcap0.8-dev amd64 1.10.0-2 [281 kB]
Des:3 http://kali.download/kali kali-rolling/main amd64 libpcap-dev amd64 1.10.0-2 [31,1 kB]
Descargados 568 kB en 2s (316 kB/s)
Seleccionando el paquete libdbus-1-dev:amd64 previamente no seleccionado.
(Leyendo la base de datos ... 312783 ficheros o directorios instalados actualmente.)
Preparando para desempaquetar .../libdbus-1-dev_1.12.20-2_amd64.deb ...
Desempaquetando libdbus-1-dev:amd64 (1.12.20-2) ...
Seleccionando el paquete libpcap0.8-dev:amd64 previamente no seleccionado.
Preparando para desempaquetar .../libpcap0.8-dev_1.10.0-2_amd64.deb ...
Desempaquetando libpcap0.8-dev:amd64 (1.10.0-2) ...
Seleccionando el paquete libpcap-dev:amd64 previamente no seleccionado.
Preparando para desempaquetar .../libpcap-dev_1.10.0-2_amd64.deb ...
Desempaquetando libpcap-dev:amd64 (1.10.0-2) ...
Configurando libdbus-1-dev:amd64 (1.12.20-2) ...
Procesando disparadores para man-db (2.9.4-2) ...
Procesando disparadores para sgml-base (1.30) ...
Procesando disparadores para kali-menu (2021.2.3) ...
Configurando libpcap0.8-dev:amd64 (1.10.0-2) ...
Configurando libpcap-dev:amd64 (1.10.0-2) ...


-----
❯ python setup.py build
running build
running build_py
running build_ext
building 'cpyrit._cpyrit_cpu' extension
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=f
ormat-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu.c -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o -Wall -fno-strict-aliasing -DVERSION="0.5.1" -maes -mpclmul
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=f
ormat-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu_sse2.S -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu_sse2.o -Wall -fno-strict-aliasing -DVERSION="0.5.1" -maes -mpclmu
l                                              
x86_64-linux-gnu-gcc -pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-z,relro -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -Wdate-time -D_FORTIFY_SOURCE=2 -g
-ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -Wl,-z,relro -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/buil
d/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o build/temp.linux-x86_64-2.7/cpyrit/_cpy
rit_cpu_sse2.o -lcrypto -lpcap -o build/lib.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.so             
running build_scripts
creating build/scripts-2.7
copying and adjusting pyrit -> build/scripts-2.7
changing mode of build/scripts-2.7/pyrit from 644 to 755


-----
❯ sudo python setup.py install
running install
running build
running build_py
running build_ext
running build_scripts
running install_lib
copying build/lib.linux-x86_64-2.7/pyrit_cli.py -> /usr/local/lib/python2.7/dist-packages
creating /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/config.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/util.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/pckttools.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/storage.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/cpyrit.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/__init__.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/network.py -> /usr/local/lib/python2.7/dist-packages/cpyrit
copying build/lib.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.so -> /usr/local/lib/python2.7/dist-packages/cpyrit
byte-compiling /usr/local/lib/python2.7/dist-packages/pyrit_cli.py to pyrit_cli.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/config.py to config.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/util.py to util.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/pckttools.py to pckttools.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/storage.py to storage.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/cpyrit.py to cpyrit.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/__init__.py to __init__.pyc
byte-compiling /usr/local/lib/python2.7/dist-packages/cpyrit/network.py to network.pyc
writing byte-compilation script '/tmp/tmpHmQDhu.py'
/usr/bin/python -O /tmp/tmpHmQDhu.py
removing /tmp/tmpHmQDhu.py
running install_scripts
copying build/scripts-2.7/pyrit -> /usr/local/bin
changing mode of /usr/local/bin/pyrit to 755
running install_egg_info
Writing /usr/local/lib/python2.7/dist-packages/pyrit-0.5.1.egg-info

-----
## PYrit
❯ pyrit
Traceback (most recent call last):
  File "/usr/local/bin/pyrit", line 4, in <module>
    import pyrit_cli
  File "/usr/local/lib/python2.7/dist-packages/pyrit_cli.py", line 32, in <module>
    import cpyrit.cpyrit
  File "/usr/local/lib/python2.7/dist-packages/cpyrit/cpyrit.py", line 42, in <module>
    import util
  File "/usr/local/lib/python2.7/dist-packages/cpyrit/util.py", line 54, in <module>
    import _cpyrit_cpu
ImportError: /usr/local/lib/python2.7/dist-packages/cpyrit/_cpyrit_cpu.so: undefined symbol: aesni_key

-------------
## COMENTAR LINEAS
❯ nano cpyrit/cpufeatures.h (linea 37)
34 #endif
35
36 #if (defined(__AES__) && defined(__PCLMUL__))
37     #define COMPILE_AESNI
38 #endif
39
40 #endif /* CPUFEATURES */
41

34 #endif
35
36 #if (defined(__AES__) && defined(__PCLMUL__))
37 //    #define COMPILE_AESNI
38 #endif
39
40 #endif /* CPUFEATURES */
41

-----
nano cpyrit/_cpyrit_cpu.c (1080-1143)
1079 /*
1080 #ifdef COMPILE_AESNI
1081     inline __m128i
1082     aesni_key(__m128i a, __m128i b)
1083     {
1084         __m128i t;
1085
1086         b = _mm_shuffle_epi32(b, 255);
1087         t = _mm_slli_si128(a, 4);
[...]
1137             if (memcmp(crib, S0, 6) == 0)
1138                 return i;
1139         }
1140
1141         return -1;
1142     }
1143 #endif /* COMPILE_AESNI */
1144 */
1145 PyDoc_STRVAR(CCMPCracker_solve__doc__,
1146              "solve(object) -> solution or None\n\n"

-----
❯ sudo python setup.py install
running install     
running build                                                                                  
running build_py                                                                               
running build_ext                                                                              
building 'cpyrit._cpyrit_cpu' extension                                                        
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=f
ormat-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu.c -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o -Wall -fno-strict-aliasing -DVERSION="0.5.1" -maes -mpclmul
x86_64-linux-gnu-gcc -pthread -fno-strict-aliasing -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=f
ormat-security -fPIC -I/usr/include/python2.7 -c cpyrit/_cpyrit_cpu_sse2.S -o build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu_sse2.o -Wall -fno-strict-aliasing -DVERSION="0.5.1" -maes -mpclmu
l                                                                                              
x86_64-linux-gnu-gcc -pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-z,relro -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -Wdate-time -D_FORTIFY_SOURCE=2 -g
-ffile-prefix-map=/build/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -Wl,-z,relro -Wdate-time -D_FORTIFY_SOURCE=2 -g -ffile-prefix-map=/buil
d/python2.7-vgIf7a/python2.7-2.7.18=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC build/temp.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.o build/temp.linux-x86_64-2.7/cpyrit/_cpy
rit_cpu_sse2.o -lcrypto -lpcap -o build/lib.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.so
running build_scripts                                                                          
running install_lib                                                                            
copying build/lib.linux-x86_64-2.7/cpyrit/_cpyrit_cpu.so -> /usr/local/lib/python2.7/dist-packages/cpyrit
writing byte-compilation script '/tmp/tmpZo7Ogf.py'                 
/usr/bin/python -O /tmp/tmpZo7Ogf.py                                                           
removing /tmp/tmpZo7Ogf.py                                                                     
running install_scripts                                                                        
changing mode of /usr/local/bin/pyrit to 755                                                   
running install_egg_info                                                                       
Removing /usr/local/lib/python2.7/dist-packages/pyrit-0.5.1.egg-info           
Writing /usr/local/lib/python2.7/dist-packages/pyrit-0.5.1.egg-info

------
❯ pyrit                                                                               
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora                                 
https://github.com/JPaulMora/Pyrit                                                    
This code is distributed under the GNU General Public License v3+                     

Usage: pyrit [options] command                                                        

Recognized options:                                                                   
  -b               : Filters AccessPoint by BSSID                                     
  -e               : Filters AccessPoint by ESSID                                     
  -h               : Print help for a certain command          
  -i               : Filename for input ('-' is stdin)                                
  -o               : Filename for output ('-' is stdout)                              
  -r               : Packet capture source in pcap-format                             
  -u               : URL of the storage-system to use                             
  --all-handshakes : Use all handshakes instead of the best one               
  --aes            : Use AES                                                          

Recognized commands:                                                                  
  analyze                 : Analyze a packet-capture file
  attack_batch            : Attack a handshake with PMKs/passwords from the db
  attack_cowpatty         : Attack a handshake with PMKs from a cowpatty-file        
  attack_db               : Attack a handshake with PMKs from the db
  attack_passthrough      : Attack a handshake with passwords from a file             
  batch                   : Batchprocess the database               
  benchmark               : Determine performance of available cores          
  benchmark_long          : Longer and more accurate version of benchmark (5 minutes)
  check_db                : Check the database for errors        
  create_essid            : Create a new ESSID                                        
  delete_essid            : Delete a ESSID from the database                          
  eval                    : Count the available passwords and matching results        
  export_cowpatty         : Export results to a new cowpatty file          
  export_hashdb           : Export results to an airolib database                     
  export_passwords        : Export passwords to a file                      
  help                    : Print general help                                        
  import_passwords        : Import passwords from a file-like source
  import_unique_passwords : Import unique passwords from a file-like source    
  list_cores              : List available cores                       
  list_essids             : List all ESSIDs but don't count matching results  
  passthrough             : Compute PMKs and write results to a file           
  relay                   : Relay a storage-url via RPC               
  selftest                : Test hardware to ensure it computes correct results       
  serve                   : Serve local hardware to other Pyrit clients               
  strip                   : Strip packet-capture files to the relevant packets        
  stripLive               : Capture relevant packets from a live capture-source       
  verify                  : Verify 10% of the results by recomputation                

-----
❯ cd test
❯ ls
 dict.gz   test_pyrit.py   wpa2psk-2WIRE972.dump.gz   wpa2psk-linksys.dump.gz   wpa2psk-MOM1.dump.gz   wpa2psk-Red_Apple.dump.gz   wpapsk-linksys.dump.gz   wpapsk-virgin_broadband.dump.gz
❯ gunzip *
gzip: test_pyrit.py: unknown suffix -- ignored
❯ ls
 dict   test_pyrit.py   wpa2psk-2WIRE972.dump   wpa2psk-linksys.dump   wpa2psk-MOM1.dump   wpa2psk-Red_Apple.dump   wpapsk-linksys.dump   wpapsk-virgin_broadband.dump


------
## probando
❯ file wpa2psk-2WIRE972.dump
wpa2psk-2WIRE972.dump: pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11, capture length 65535)
❯ pyrit -r wpa2psk-2WIRE972.dump analyze
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'wpa2psk-2WIRE972.dump' (1/1)...
Parsed 568 packets (568 802.11-packets), got 9 AP(s)

#1: AccessPoint 00:23:51:9e:f9:11 ('2WIRE061'):
#2: AccessPoint 00:1d:5a:d9:e9:51 ('2WIRE503'):
#3: AccessPoint 00:24:56:6c:64:09 ('2WIRE784'):
#4: AccessPoint 00:25:3c:86:0b:69 ('2WIRE897'):
#5: AccessPoint 00:40:10:20:00:03 ('2WIRE972'):
  #1: Station 00:18:41:9c:a4:a0, 1 handshake(s):
    #1: HMAC_SHA1_AES, good, spread 1
#6: AccessPoint 00:1d:5a:84:6a:c9 ('Ananda'):
#7: AccessPoint 00:1f:b3:9f:2a:a1 ('Carnegie339'):
#8: AccessPoint 00:14:bf:81:7a:97 ('Hardrock'):
#9: AccessPoint 00:0f:66:4a:18:b1 ('Narra'):


❯ pyrit
zsh: command not found: pyrit









Si visualizamos la version de scapy
❯ scapy
INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().

                     aSPY//YASa       
             apyyyyCY//////////YCa       |
            sY//////YSpcs  scpCY//Pp     | Welcome to Scapy
 ayp ayyyyyyySCP//Pp           syY//C    | Version 2.4.4
 AYAsAYYYYYYYY///Ps              cY//S   |
         pCCCCY//p          cSSps y//Y   | https://github.com/secdev/scapy
         SPPPP///a          pP///AC//Y   |
              A//A            cyP////C   | Have fun!
              p///Ac            sC///a   |
              P////YCpc           A//A   | Craft packets before they craft
       scccccp///pSP///p          p//Y   | you.
      sY/////////y  caa           S//P   |                      -- Socrate
       cayCyayP//Ya              pY/Ya   |
        sY/PsY////YCc          aC//Yp
         sc  sccaCY//PCypaapyCP//YSs  
                  spCPY//////YPSps    
                       ccaacs         


-----
Dentro de la carpeta pyrit

❯ grep -r -i -l "scapy" 2>/dev/null
pyrit_cli.py
test/test_pyrit.py
build/lib.linux-x86_64-2.7/pyrit_cli.py
build/lib.linux-x86_64-2.7/cpyrit/util.py
build/lib.linux-x86_64-2.7/cpyrit/pckttools.py
cpyrit/util.py
cpyrit/pckttools.py

❯ cat pyrit_cli.py | grep -i "scapy"
                    raise PyritRuntimeError("Scapy 2.x is required to use " \


------
instalandando scapy 2.3.2
❯ pip install scapy==2.3.2
Collecting scapy==2.3.2
  Downloading scapy-2.3.2.tar.gz (1.1 MB)
     |████████████████████████████████| 1.1 MB 10.0 MB/s
    ERROR: Command errored out with exit status 1:
     command: /usr/bin/python3 -c 'import sys, setuptools, tokenize; sys.argv[0] = '"'"'/tmp/pip-install-bum2u58w/scapy_024a50b11e8547cca824fac782c3f89d/setup.py'"'"'; __file__='"'"'/tmp/pip-install-bum2u58w/scapy_024a50b11e8547cca824fac782c3f89d/setup.py'"'"';f=getattr(tokenize, '"'"'open'"'"', open)(__file__);code=f.read().replace('"'"'\r\n'"'"', '"'"'\n'"'"');f.close();exec(compile(code, __file__, '"'"'exec'"'"'))' egg_info --egg-base /tmp/pip-pip-egg-info-9u72r63q
         cwd: /tmp/pip-install-bum2u58w/scapy_024a50b11e8547cca824fac782c3f89d/
    Complete output (6 lines):
    Traceback (most recent call last):
      File "<string>", line 1, in <module>
      File "/tmp/pip-install-bum2u58w/scapy_024a50b11e8547cca824fac782c3f89d/setup.py", line 35
        os.chmod(fname,0755)
                          ^
    SyntaxError: leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers
    ----------------------------------------
WARNING: Discarding https://files.pythonhosted.org/packages/6d/72/c055abd32bcd4ee6b36ef8e9ceccc2e242dea9b6c58fdcf2e8fd005f7650/scapy-2.3.2.tar.gz#sha256=a9059ced6e1ded0565527c212f6ae4c735f4245d0f5f2d7313c4a6049b005cd8 (from https://pypi.org/simple/scapy/). Command errored out with exit status 1: python setup.py egg_info Check the logs for full command output.
ERROR: Could not find a version that satisfies the requirement scapy==2.3.2
ERROR: No matching distribution found for scapy==2.3.2

## DESCARGA
❯ wget https://files.pythonhosted.org/packages/6d/72/c055abd32bcd4ee6b36ef8e9ceccc2e242dea9b6c58fdcf2e8fd005f7650/scapy-2.3.2.tar.gz
--2021-08-18 13:16:34--  https://files.pythonhosted.org/packages/6d/72/c055abd32bcd4ee6b36ef8e9ceccc2e242dea9b6c58fdcf2e8fd005f7650/scapy-2.3.2.tar.gz
Resolviendo files.pythonhosted.org (files.pythonhosted.org)... 151.101.1.63, 151.101.65.63, 151.101.129.63, ...
Conectando con files.pythonhosted.org (files.pythonhosted.org)[151.101.1.63]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1130191 (1,1M) [application/octet-stream]
Grabando a: «scapy-2.3.2.tar.gz»

scapy-2.3.2.tar.gz                              100%[=====================================================================================================>]   1,08M  6,78MB/s    en 0,2s

2021-08-18 13:16:34 (6,78 MB/s) - «scapy-2.3.2.tar.gz» guardado [1130191/1130191]


❯ gunzip scapy-2.3.2.tar.gz
❯ tar -xf scapy-2.3.2.tar
❯ ls
 scapy-2.3.2   scapy-2.3.2.tar

❯ sudo python setup.py install

❯ scapy
INFO: Can't import python gnuplot wrapper . Won't be able to plot.
INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().
WARNING: No route found for IPv6 destination :: (no default route?)
INFO: Can't import python Crypto lib. Won't be able to decrypt WEP.
INFO: Can't import python Crypto lib. Disabled certificate manipulation tools
Welcome to Scapy (2.3.2)


----
