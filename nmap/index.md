# Nmap Cheat Sheet

I will describe the `nmap` tool in detail and ways to use the tool precisely especially for penetration testers.
<!--more-->

##  Introduction
`Nmap` is a free and open source tool which is especially used for scanning and identifying the open `ports` i.e. discovery hosts. There are a total of `65535` available ports; This tool is especially used for initial enumeration .

## Scan types
### Target specification
#### Just to scan with IP address
```bash
root@gr4n173:~$ nmap 10.150.150.10
```
#### To scan the multiple targets with IP range
```bash
root@gr4n173:~$ nmap 10.150.150.1-254
```
#### Scan whole network 
Sometimes we wish to scan a whole network of adjacent hosts. This `nmap` supports `CIDR-style` addressing. We just have to append `/<numbits>` to an ip address or hostname for example:-
hostname, ip address, networks. 
```bash
root@gr4n173:~$ nmap 10.150.150.10/24
```

### Host Discovery
Scanning every port of every single ip address is slow and usually necessary. So `host discovery` or `ping scan` comes into play i.e. this will demonstrate that ip addresses which are actually active. 

#### List the target hosts(`-sL`)
This can be done using `List Scan` as `-sL` and this can't be combined with port scanning, os detection, host discovery.

```bash
root@gr4n173:~$ nmap -sL google.com
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 14:38 +0545
Nmap scan report for google.com (172.217.160.142)
Other addresses for google.com (not scanned): 2404:6800:4007:80a::200e
rDNS record for 172.217.160.142: maa03s29-in-f14.1e100.net
Nmap done: 1 IP address (0 hosts up) scanned in 0.09 seconds
```

#### No port scan ( `-sn`)
In order to host discovery without port scan and only print out the available hosts that respond to host discovery we can use `-sn` options. This can be combined with any of the discovery probe types( `-P*`) for greater flexibility. To identify the running host without `port scan/host discovery` we can combine it with 

```bash
root@gr4n173:~$ nmap -sn -Pn 10.150.150.10-15
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 14:44 +0545
Nmap scan report for 10.150.150.10
Host is up.
Nmap scan report for 10.150.150.11
Host is up.
Nmap scan report for 10.150.150.12
Host is up.
Nmap scan report for 10.150.150.13
Host is up.
Nmap scan report for 10.150.150.14
Host is up.
Nmap scan report for 10.150.150.15
Host is up.
Nmap done: 6 IP addresses (6 hosts up) scanned in 0.02 seconds	
```

#### No ping ( `-Pn`)
Without `ping` and host discovery we can determine the `open port` with `-Pn` . Here we already have to know the active ip address so, this scan assumes the given ip is active.
```bash
root@gr4n173:~$ nmap -Pn 10.150.150.11
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower. 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 14:55 +0545
Nmap scan report for 10.150.150.11
Host is up (0.19s latency).
Not shown: 985 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
```

### Port Scanning
Basic states involved in port scan are open, closed, filtered, unfiltered. All these states are same as their basic meaning except unfiltered; it can be combined with other scans like `Window Scan`, `SYN Scan` or `FIN Scan` which helps to identify whether the port is open or not. In port scanning we required `administrator` privileges. 
#### Techniques involved

**1. SYN Scan (`-sS`)**

This scan is known as `TCP SYN Scan`and is default i.e. it can be performed quickly, scanning thousands of ports per second on a fast network not hampered by restrictive firewalls. 
```bash
root@gr4n173:~$ sudo nmap -sS 10.150.150.12-20
Nmap scan report for 10.150.150.12
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE                      
21/tcp open  ftp                          
22/tcp open  ssh                          

Nmap scan report for 10.150.150.18
Host is up (0.20s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE                      
22/tcp open  ssh                          
80/tcp open  http
```
**2.Connect Scan**(`-sT`)

When we don't have admin privileges we can use `TCP connect scan` which gives same result as that of `SYN scan`. So if we have admin privileges we are advised to use syn scan rather than connect scan.
```bash
root@gr4n173:~$ nmap -sT 10.150.150.200-205
Nmap scan report for 10.150.150.202
Host is up (0.19s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
88/tcp   open  kerberos-sec
445/tcp  open  microsoft-ds
3031/tcp open  eppc
3689/tcp open  rendezvous

Nmap scan report for 10.150.150.212
Host is up (0.20s latency).
Not shown: 986 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
```
**3. UDP Scans**

UDP Services are widely deployed. DNS, SNMP and DHCP (registered ports 53,161/162, 67/68) are commonly used. Scan is activated with `-sU`options and can be combined with tcp scan type such as `SYN scan`(`-sS`) to check both protocols during the same run.
```bash
root@gr4n173:~$ sudo nmap -sU 10.150.150.10
```

### Port Specification and Scan order
#### Scan only specific ports(`-p`)
Scanning specified ports is done so as to scan only required ports and we can define the ranges using hyphen as (1-100). We can define which types of protocol as `T:` for tcp and `U:` for UDP. Similarly in order to scan all the ports `-p-` is specified which will scan from 1 to 65535 ports.
```bash
root@gr4n173:~$ nmap -p 1-10000 10.150.150.11
Nmap scan report for 10.150.150.12
Host is up (0.20s latency).
Not shown: 9998 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 269.13 seconds
```
#### Exclude the specified ports for scanning (`--exclude-ports`)
This is the same as that of specified ports scanning.
```bash
root@gr4n173:~$ nmap --exclude-ports 1-10000 10.150.150.11
```

#### Fast Scan (`-F`)
Basically when `nmap` scans the most common port 1,000 ports are scanned but with this it will reduce to `100`	. This option will only scan ports that are named in the service file.
```bash
root@gr4n173:~$ nmap -F 10.150.150.11
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 16:13 +0545
Nmap scan report for 10.150.150.11
Host is up (0.20s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 2.07 seconds
```

#### Top ports (`--top-ports <n>`) 
In order to scan the top ports we have to specify the highest number to be searched.
```bash
root@gr4n173:~$ nmap --top-ports 1000 10.150.150.11
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 16:15 +0545
Stats: 0:00:30 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 99.55% done; ETC: 16:16 (0:00:00 remaining)
Nmap scan report for 10.150.150.11
Host is up (0.19s latency).
Not shown: 985 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
```

### Version Detection
Determining the version and service of a certain port helps to dig deeper so that we can exploit the certain service of a specific version. We can use `-sV` for `version detection` .
```bash
root@gr4n173:~$ nmap -sV 10.150.150.11
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 16:23 +0545
Nmap scan report for 10.150.150.12
Host is up (0.24s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.83 seconds
```

### OS Detection
Nmap best feature is remote os detection using tcp/ip stack fingerprinting. Here nmap will sends a series of TCP and UDP packets to the remote host and examines pratically every bit in the responses. Nmap will compares the results to its nmap-os-db database of more than 2,600 known OS fingerprints and prints out the OS details if matched. 
OS can be detected using `-O` options as 
```bash 
root@gr4n173:~$ sudo nmap -sV -O 10.150.150.11
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 16:29 +0545
Nmap scan report for 10.150.150.12
Host is up (0.19s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
open  ssl/http       Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.9)[85/1339]
445/tcp   open  microsoft-ds   Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1433/tcp  open  ms-sql-s       Microsoft SQL Server 2012 11.00.2100; RTM

TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=6/18%OT=21%CT=7%CU=33980%PV=Y%DS=2%DC=I%G=Y%TM=60CC78A
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M5
OS:4DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

### Nmap Scripting Engine(NSE)

NSE can be used for vulnerability detection, network discovery, backdoor detection, vulnerability exploitation etc. 

**1. Default (`-sC`)**

Performs a script scan with the default set of scripts. Some of the scripts are considerably intrusive and shouldn't run against the target network without permission.
```bash
root@gr4n173:~$ nmap -sC 10.150.150.11
Nmap scan report for 10.150.150.11
Host is up (0.19s latency).
Not shown: 985 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: PwnDrive - Your Personal Online Storage
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
| http-cookie-flags:
|   /:
|     PHPSESSID:
|       secure flag not set and HTTPS in use
|_      httponly flag not set
|_http-title: Bad request!
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
```
**2. Run scripts (`--script`)**

To run the scripts using comma separated list of filenames, script, directories etc we can use this options as 
```bash
root@gr4n173:~$ nmap --script "smb-vuln-*" 10.150.150.11
Nmap scan report for 10.150.150.11
Host is up (0.19s latency).
Not shown: 985 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds

Host script results:                      
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:                           
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
	 Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 16.72 seconds
```
**3.To update the database**

We can update the database of `nmap exploit` as `--script-updatedb`.
```bash
root@gr4n173:~$ nmap --script-updatedb
```

### Timing and performance

When it comes to scanning with `nmap` performance has been a top priority with the utilization of parallelism tasks.
#### Set a timing template(`-T<0-5>`)
Nmap has the option of setting six templates. These numbers are  `paranoid` (`0`), `sneaky` (`1`), `polite` (`2`), `normal` (`3`), `aggressive` (`4`), and `insane` (`5`). 

- **paranoid scan**

The main effects of `T0` are serializing the scan so only one port is scanned at a time, and waiting five minutes between sending each probe.
```bash
root@gr4n173:~$ nmap 10.150.150.10 -T0
```
- **sneaky scan**

This scan will avoid IDS alerts, they will take an extraordinarily long time to scan thousands of machines or ports.
```bash
root@gr4n173:~$ nmap 10.150.150.10 -T1
```
- **polite scan**

This scan is similar to the `-T0` and `-T1` but it is a bit faster than those. It will slow down the scan to use less bandwidth and target machine resources.
```bash
root@gr4n173:~$ nmap 10.150.150.10 -T2
```
- **normal scan**

This scan is Nmap's default behavior, which includes parallelization.
```bash
root@gr4n173:~$ nmap 10.150.150.10 -T3
```
- **aggressive scan**

This scan will prohibit the dynamic scan delay from exceeding 10 ms for TCP ports. I would always recommend using this type of scan. 
```bash
root@gr4n173:~$ nmap 10.150.150.10 -T4
```
- **insane scan**
Scan is really insane that it can't give you a correct and precise scan.
```bash
root@gr4n173:~$ nmap 10.150.150.10 -T5
```

#### Specifying the speed rates

Usually scanning all ports of a certain target is too slow so we can specify the lowest speed of scanning and can't scan `300` packets per sec as below.
```bash
root@gr4n173:~$ nmap --min-rate 300 10.150.150.10
```
We can also limit the `max rate` of sending the packet as `100` packets per sec.
```bash
root@gr4n173:~$ nmap --max-rate 100 10.150.150.10
```
	
### Output

Basically we can output in three forms: normal, xml and grepable format.
1. Normal format
```bash
root@gr4n173:~$ nmap -oN scan 10.150.150.10
```
2. xml format
```bash
root@gr4n173:~$ nmap -oX scan 10.150.150.10
```
3. grepable format
```bash
root@gr4n173:~$ nmap -oG scan 10.150.150.10
```
  
## Combining all those from above
We can scan ip `10.150.150.10` for top 10000 ports along with version, script scan and saving it as normal format in file nmap.txt. 
```bash
root@gr4n173:~$ sudo nmap -sV -sC -oN nmap.txt -Pn 10.150.150.10
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-18 16:29 +0545
Nmap scan report for 10.150.150.10
Host is up (0.19s latency).
Not shown: 98 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
open  ssl/http       Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.9)[85/1339]
[snippet]
```
## This is how I nmap
Normally, at first I scan all the ports with `min-rate` to `10000` so that I can identify opened ports and then I go for `script`, `version` run with defined ports and save it to normal to review later.
```bash
root@gr4n173:~$ sudo nmap -p- --min-rate 10000 -oN nmap-ports.txt 10.150.150.10
Nmap scan report for 10.150.150.10
Host is up (0.19s latency).
Not shown: 985 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 7.62 seconds
```
```bash
root@gr4n173:~$ sudo nmap -p 21, 80, 135, 139, 443, 445, 1433, 3306, 5040, 7680, 49664, 49665, 49666, 49667, 49668 -sC -sV -oN opened-ports-services.txt 10.150.150.10
Nmap scan report for 10.150.150.10
Host is up (0.19s latency).
Not shown: 985 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: PwnDrive - Your Personal Online Storage
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
| http-cookie-flags:
|   /:
|     PHPSESSID:
|       secure flag not set and HTTPS in use
|_      httponly flag not set
|_http-title: Bad request!
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s

3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL, WMSRequest: 
|_    Host '10.150.150.10' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=2/20%Time=60315D9B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4A,"F\0\0\x01\xffj\x04Host\x20'10\.150\.150\.10'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(WMSRequest,4
SF:A,"F\0\0\x01\xffj\x04Host\x20'10\.150\.150\.10'\x20is\x20not\x20allowed\x
SF:20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m32s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-20T19:11:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.89 seconds
```
## Conclusion 
Having the idea to use `nmap` precisely plays a great role for penetration testers due to its ease of use, accuracy, flexibility and high performance. Though you can find many `nmap cheat sheets` you can refer to them. I have blogged this just to keep as further reference for myself. If you have any problem related to the functionality of `nmap` then you can visit the main page of nmap.
Thanks for staying with me throughout this blog and hope you have learned some new techniques.

## Resources
1. https://nmap.org/book/man.html
2. https://www.tutorialspoint.com/nmap-cheat-sheet
3. https://en.wikipedia.org/wiki/Nmap
4. https://hakin9.org/nmap-cheat-sheet/

