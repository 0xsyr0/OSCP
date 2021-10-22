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

### Vulnerability Analysis
| Tool | URL |
| --- | --- |
| nmap | https://github.com/nmap/nmap |
| Nuclei | https://github.com/projectdiscovery/nuclei |

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
#### vi
```c

```

#### tmux
```c

```

### Information Gathering
#### DNS
##### Reverse DNS
```c
host <remote_ip> <remote_ip>
dig axfr @<remote_ip> <domain>           // zone transfer - needs tcp DNS - port 53
host -l <domain> <remote_ip>
```
