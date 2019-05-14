# ELF x86 - Format string bug basic 3
https://www.root-me.org/en/Challenges/App-System/ELF-x86-Format-string-bug-basic-3
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
SSH access 	ssh -p 2222 app-systeme-ch17@challenge02.root-me.org  
Username	app-systeme-ch17
Password	app-systeme-ch17
```

After a quick look at the source code, the vulnerable code can be spotted at
line 31, which contains a **sprintf** function with controllable format string:
```c
char    outbuf[512];
char    buffer[512];
char    user[12];
[... snip ...]

fgets(user, sizeof(user), stdin);
user[strlen(user) - 1] = '\0';
[... snip ...]

sprintf (buffer, "ERR Wrong user: %400s", user);
sprintf (outbuf, buffer);
```
First, let's verify it:
```gdb
(gdb) break *0x0804854f
Breakpoint 1 at 0x804854f
(gdb) run
Starting program: /challenge/app-systeme/ch17/ch17
Username: %p

Breakpoint 1, 0x0804854f in main ()
(gdb) x/1s 0xbffff97c
0xbffff97c:	"ERR Wrong user:", ' ' <repeats 185 times>...
(gdb) x/1s 0xbffffa35
0xbffffa35:	' ' <repeats 200 times>...
(gdb) x/1s 0xbffffb00
0xbffffb00:	' ' <repeats 26 times>, "0xbffff770"
```

Well, it prints an address from the stack.<br>
However, it seems there are 2 limitations:
1. The user's input is limited to 12 - (null byte) - (last byte set to null) =
10 bytes.
2. Before calling the vulnerable **sprintf**, the user input is transformed into
a fixed-size 416 bytes buffer (```ERR Wrong user: %400s```).

The first limitation pretty much disqualifies the exploit:
```
        4 bytes      2-6 bytes   +2 bytes
  < write address > < padding > <   %n    >
```
Then, we'll need to find an other way to exploit this program.<br>
I don't know any shellcode that spawns a shell, with less than 10 bytes.
Therefore, it can be guessed that the shellcode should be in an environment
variable.<br><br>

Now, let's try to find an address that is already in stack that can be
overwritten. The next addresses where found:
```
  offset |  address   |
  -------+------------+-------------------------------
  1      | 0xbffff770 | the user's input
  241    | 0xbffffb30 | ?
  242    | 0x80482a4  | ret address (__libc_start_main)
  248    | 0xbffffb5e | ?
  255    | 0xbffffd40 | argv[0]

  0xbffffb88
```
