# ELF x86 - Remote Format String bug
https://www.root-me.org/en/Challenges/App-System/ELF32-Remote-Format-String-bug
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
Protocol	TCP
Port	        56032
SSH access 	ssh -p 2222 app-systeme-ch32@challenge02.root-me.org   
Username	app-systeme-ch32
Password	app-systeme-ch32
```
According to the source code (and the title gives it away), the vulnerable code presents in the _recv_loop_ function at line 42:
```c
recv(csock, input, LENGTH-1, 0);
snprintf (output, sizeof (output), input);
```
According to the documentation of **snprintf**, it gets 3 or more arguments. The first one is the target buffer, the second is the buffer's length, the third is the format string and afterwards any number of arguments (varargs).<br>
As one may notice, the format string at the code above is actually the data passed by the client via the socket. Which means an attacker can control the format string and perform an attack on the stack using it.<br><br>
Let's verify it quickly:
```sh
$ nc challenge02.root-me.org 56032
%p %p %p %p 
(nil) (nil) 0x10 0x4
```
As one may see, the input string (```%p %p %p %p```) pops 4 pointers/values from the stack (```(nil) (nil) 0x10 0x4```).<br><br>

[TBC]
