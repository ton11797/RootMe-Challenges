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
So the plan is to spawn a shell using a vulnerability in **ch45** (stack overflow duh), in order to get the _app-systeme-ch45-cracked_ permissions, so we'll be able to read the **.passwd** file (which is owned by _app-systeme-ch45-cracked_).<br><br>

[To be continued]
