# ELF ARM - Basic Crackme
https://www.root-me.org/en/Challenges/Cracking/ELF-ARM-basic-crackme
```
Get the validation password.
```

We can run the binary in a QEMU emulator, but let's try to reverse it statically.<br><br>

The according to ```arm-linux-gnueabihf-objdump -x ch23.bin```, the architecture is elf32-littlearm and the start address is 0x83b8.
But, around the start address there is a jump to ```__libc_start_main@plt```. So we'll have to work a bit to find the main entry point.<br><br>

According to the command ```strings ch23.bin```, there is a ```Checking %s for password...``` string in the binary.<br>
After a quick ```arm-linux-gnueabihf-objdump -s -j .rodata ch23.bin```, the address of this string seems to be 0x8654.<br>
Using the command ```arm-linux-gnueabihf-objdump -D ch23.bin | grep 8654```, it's pretty clear that the printing of this string is at address 0x84b0:
```asm
84b0:       e51b3024        ldr     r3, [fp, #-36]  ; 0xffffffdc
84b4:       e5933004        ldr     r3, [r3, #4]
84b8:       e50b3018        str     r3, [fp, #-24]  ; 0xffffffe8
84bc:       e59f3194        ldr     r3, [pc, #404]  ; 8658 <abort@plt+0x2ac>
84c0:       e1a00003        mov     r0, r3
84c4:       e51b1018        ldr     r1, [fp, #-24]  ; 0xffffffe8
84c8:       ebffffa5        bl      8364 <printf@plt>
```
The string "Checking %s for password..." is a format string. So when the _printf_ function is called, the given password string should be passed as the second parameter (R1).<br>
According to address 0x84c4, **fp-24** should contain the given password.<br>
So, the given password is a local variable (it's presented in the stack) and we know its location.<br>
Let's check the next code block:
```asm
84cc:       e51b0018        ldr     r0, [fp, #-24]  ; 0xffffffe8
84d0:       ebffffb2        bl      83a0 <strlen@plt>
84d4:       e1a03000        mov     r3, r0
84d8:       e50b301c        str     r3, [fp, #-28]  ; 0xffffffe4
84dc:       e51b301c        ldr     r3, [fp, #-28]  ; 0xffffffe4
84e0:       e3530006        cmp     r3, #6
84e4:       0a000003        beq     84f8 <abort@plt+0x14c>
84e8:       e59f016c        ldr     r0, [pc, #364]  ; 865c <abort@plt+0x2b0>
84ec:       ebffff9f        bl      8370 <puts@plt>
84f0:       e51b001c        ldr     r0, [fp, #-28]  ; 0xffffffe4
84f4:       ebffffa6        bl      8394 <exit@plt>
```
The first 2 instructions are calling the _strlen_ function on the given password. Afterward, it will put the result in a local variable (at fp-28 addresss) and will compare it to 6.<br>
If the password's length equals to 6, then the program will jump to the address 0x84f8 (one instruction after this block).<br>
Otherwise, it will load an address of a string (0x865c), print it and will call the exit function.<br>
Just to be sure, let's check the string in the address 0x865c.<br>
According to ```arm-linux-gnueabihf-objdump -s -j .rodata ch23.bin```, the string is "Loser".<br>
So in order to solve the challenge, the password's length should be 6.<br><br>

Continuing to the next code block:
```asm
84f8:       e51b4010        ldr     r4, [fp, #-16]
84fc:       e51b0018        ldr     r0, [fp, #-24]  ; 0xffffffe8
8500:       ebffffa6        bl      83a0 <strlen@plt>
8504:       e1a03000        mov     r3, r0
8508:       e0633004        rsb     r3, r3, r4
850c:       e50b3010        str     r3, [fp, #-16]
8510:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
8514:       e5d32000        ldrb    r2, [r3]
8518:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
851c:       e2833005        add     r3, r3, #5
8520:       e5d33000        ldrb    r3, [r3]
8524:       e1520003        cmp     r2, r3
8528:       0a000002        beq     8538 <abort@plt+0x18c>
```
The first instruction is loading the password's length to R4 (stored in the stack somewhere in the code - not so important).<br>
Then _strlen_ called for the given password. Next, it will compute ```R3 = R3 - R4```. Obviously, in the end of ```R3, R3, R4```, ```R3=0```.<br>
Afterward it will store R3 (0) to a local variable (at the address **fp-16** in the stack).<br><br>

Next, the first byte of the given password will be loaded to R2, and the 6th byte will be loaded to R3.<br>
Then, those bytes will be compared. As anyone can guess, those two bytes should be equal, so will have to make sure that **password[0] == password[5]**.<br><br>
But (again), let's see what's up if the jump is not taken:
```asm
852c:       e51b3010        ldr     r3, [fp, #-16]
8530:       e2833001        add     r3, r3, #1
8534:       e50b3010        str     r3, [fp, #-16]
```
Well, it's pretty easy to understand what's up. If the jump is not taken, the local variable **fp-16** will be increased by 1.<br>
The **fp-16** variable may be a counter of number of errors the password has, but will find out later.<br><br>

The next block is:
```asm
8538:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
853c:       e5d33000        ldrb    r3, [r3]
8540:       e2832001        add     r2, r3, #1
8544:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
8548:       e2833001        add     r3, r3, #1
854c:       e5d33000        ldrb    r3, [r3]
8550:       e1520003        cmp     r2, r3
8554:       0a000002        beq     8564 <abort@plt+0x1b8>
```
Again, R3 will contain the given password. Next, it will load the first byte, add to it 1 and will store it in R2.<br>
Afterword, R3 will contain the given password again, an will load only the second byte.<br>
Lastly, the two values are compared. So, the condition is ```password[0]+1 == password[1]```. If the jump is not taken, then again the **fp-16** variable will be increased by 1.<br><br>


The next block is:
```asm
8564:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
8568:       e2833003        add     r3, r3, #3
856c:       e5d33000        ldrb    r3, [r3]
8570:       e2832001        add     r2, r3, #1
8574:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
8578:       e5d33000        ldrb    r3, [r3]
857c:       e1520003        cmp     r2, r3
8580:       0a000002        beq     8590 <abort@plt+0x1e4>
```
In short, the sum of fourth byte and 1 is compared with the first byte - ```password[3]+1 == password[0]```.<br>
Again if the jump is not taken, then the **fp-16** variable will be increased by 1.<br><br>

```asm
8590:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
8594:       e2833002        add     r3, r3, #2
8598:       e5d33000        ldrb    r3, [r3]
859c:       e2832004        add     r2, r3, #4
85a0:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
85a4:       e2833005        add     r3, r3, #5
85a8:       e5d33000        ldrb    r3, [r3]
85ac:       e1520003        cmp     r2, r3
85b0:       0a000002        beq     85c0 <abort@plt+0x214>
```
Again, it's pretty obvious what's up so I'll make it short - the sum of the third byte and 4 is compared with the 6th byte - ```password[2]+4 == password[5]```. Again, if not **fp-16** will be increased by 1.<br><br>

```asm
85c0:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
85c4:       e2833004        add     r3, r3, #4
85c8:       e5d33000        ldrb    r3, [r3]
85cc:       e2832002        add     r2, r3, #2
85d0:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
85d4:       e2833002        add     r3, r3, #2
85d8:       e5d33000        ldrb    r3, [r3]
85dc:       e1520003        cmp     r2, r3
85e0:       0a000002        beq     85f0 <abort@plt+0x244>
```
Now, the condition is ```password[4]+2 == password[2]```.<br><br>

The last block is a bit different:
```asm
85f0:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
85f4:       e2833003        add     r3, r3, #3
85f8:       e5d33000        ldrb    r3, [r3]
85fc:       e2233072        eor     r3, r3, #114    ; 0x72
8600:       e20330ff        and     r3, r3, #255    ; 0xff
8604:       e51b2010        ldr     r2, [fp, #-16]
8608:       e0823003        add     r3, r2, r3
860c:       e50b3010        str     r3, [fp, #-16]

8610:       e51b3018        ldr     r3, [fp, #-24]  ; 0xffffffe8
8614:       e2833006        add     r3, r3, #6
8618:       e5d33000        ldrb    r3, [r3]
861c:       e51b2010        ldr     r2, [fp, #-16]
8620:       e0823003        add     r3, r2, r3
8624:       e50b3010        str     r3, [fp, #-16]
8628:       e51b3010        ldr     r3, [fp, #-16]

862c:       e3530000        cmp     r3, #0
8630:       1a000003        bne     8644 <abort@plt+0x298>
8634:       e59f0024        ldr     r0, [pc, #36]   ; 8660 <abort@plt+0x2b4>
8638:       ebffff4c        bl      8370 <puts@plt>
863c:       e3a00000        mov     r0, #0
8640:       ebffff53        bl      8394 <exit@plt>
8644:       e59f0010        ldr     r0, [pc, #16]   ; 865c <abort@plt+0x2b0>
8648:       ebffff48        bl      8370 <puts@plt>
864c:       e51b0010        ldr     r0, [fp, #-16]
8650:       ebffff4f        bl      8394 <exit@plt>
```
The first 4 instructions load the third byte to R3, _xor_ it with 0x72 and _and_ it with 0xff. So, ```R3 = (password[2] ^ 0x72) & 0xff```.<br>
Next, it will sum **fp-16** (reminder - the counter) and R3, and put it in **fp-16** - ```counter += ((password[2] ^ 0x72) & 0xff)```.<br>
Next, it will add the 7th byte (should be 0 because the password's length is 6) and will add it to the counter - ```counter += 0```.
Now, the counter is compared with 0.<br>
If the counter isn't equal to 0, then it will load a string from the address 0x865c (reminder - "Loser"), prints it and exit.<br>
So, in order to solve the challenge the counter should be 0 in the end.<br><br>

In order to keep the counter 0, it should be 0 before the changes and ```(password[3] ^ 0x72)``` should be 0.<br>
So, in order to make ```(password[3] ^ 0x72)``` equal 0, ```password[3]``` must be equal to 0x72.<br>
So, to sum up the break down of the code, the following rules apply on the password:
<ol>
  <li>The password's length should be 6.</li>
  <li>password[0] == password[5]</li>
  <li>password[0]+1 == password[1]</li>
  <li>password[3]+1 == password[0]</li>
  <li>password[2]+4 == password[5]</li>
  <li>password[4]+2 == password[2]</li>
  <li>password[3] = 0x72 = 'r'</li>
</ol>

So,<br>
&nbsp;&nbsp;&nbsp;&nbsp;```password[3] = 0x72 = 'r'```<br>
&nbsp;&nbsp;&nbsp;&nbsp;```password[0] = password[3]+1 = 0x73 = 's'```<br>
&nbsp;&nbsp;&nbsp;&nbsp;```password[5] = password[0] = 's'```<br>
&nbsp;&nbsp;&nbsp;&nbsp;```password[1] = password[0]+1 = 0x74 = 't'```<br>
&nbsp;&nbsp;&nbsp;&nbsp;```password[2] = password[5]-4 = 0x6f = 'o'```<br>
&nbsp;&nbsp;&nbsp;&nbsp;```password[4] = password[2]-2 = 0x6d = 'm'```<br><br>

After a quick arrangement, the password/flag is **storms**.<br>
Nice and basic challenge, which worths 20 points.
