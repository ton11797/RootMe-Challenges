# ELF x86 - Information leakage with Stack Smashing Protector
https://www.root-me.org/en/Challenges/App-System/ELF32-Information-leakage-with-Stack-Smashing-Protector
```
Environment configuration :
PIE 	Position Independent Executable 	 No
RelRO 	Read Only relocations 	                 Yes
NX 	Non-Executable Stack 	                 Yes
ASLR 	Address Space Layout Randomization 	 Yes
SF 	Source Fortification 	                 Yes
SSP 	Stack-Smashing Protection 	         Yes
SRC 	Source code access 	                 No

Challenge connection informations :

Host	        challenge03.root-me.org
Protocol	TCP
Port	        56529
```

No binary nor SSH connection provided this time. So a bit of fuzzing is required.

A few fuzzing attempts may require in order to get the following response:
```
Access refused! Bye...
*** stack smashing detected ***: ch29 terminated
```
This response is sent as a result of overwriting the SSP cookie. The offset to
it is 256 (at the time of writing).
The first thought the came into my mind, is to try and brute force the cookie
so the program will continue running. However if we'll succeed to so, what's next?
We still need a leak to engage ROP or basic shellcode.<br>

So, we're look for a read-primitive.<br>
After reading some articles (provided at the challenge page) about SSP, it seems that the message is actually printed like the following:
```c
printf(*** stack smashing detected ***: %s terminated\n", argv[0]);
```
It may take a while to notice it but this is actually our read-primitive.<br>
The argv array presented at the top of the stack. If we'll be able to overwrite the argv[0] with an other address, and still smashing the cookie, it suppose to write
the data at the address (that we control).

So now we'll need to find the offset to argv[0] so we can tamper it.<br>
After few tries:
```
Enter password to access this service:
Access refused! Bye...
*** stack smashing detected ***:  terminated
```
As you may notice, the "ch29" is gone. At the time of writing the offset was 184
bytes after the offset found before. It happens because the argv[0]'s LSB is getting overwritten by the null-byte of our buffer.

So after verifing it, let's try to read some of the data at the program's memory
space. Usually, 32-bit Linux's programmed are mapped to an address space that range
from 0x08040000 to 0x0804ffff. So we should try and brute force all the address
space, and see if there is anything interesting.

And it seems there is! The password is actually mapped to one of the addresses.
So after writing a python script (uploaded to this folder) to do all the above steps, the following we got
the following output:
```sh
$ python ./ch29.py
[+] Trying to find a stack smashing message... Found at 256.
[+] Trying to find a tampered message... Found at 184.
[+] Trying to brute force addresses (may take a while)... Found 1.
[+] Trying to verify the flag...
[+] Flag: <censored>
```
