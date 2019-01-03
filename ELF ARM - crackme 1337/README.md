# ELF ARM - crackme 1337
https://www.root-me.org/en/Challenges/Cracking/ELF-ARM
```
If the binary file sends you 1337 you got the right password.
```

The binary file is pretty large (~571Kb), but there is a **main** function at address 0x8290. So let's break it down.
```asm
0x00008290 <+0>:	mov	r12, sp
0x00008294 <+4>:	push	{r4, r11, r12, lr, pc}
0x00008298 <+8>:	sub	r11, r12, #4
0x0000829c <+12>:	sub	sp, sp, #36	; 0x24
0x000082a0 <+16>:	str	r0, [r11, #-40]	; 0x28
0x000082a4 <+20>:	str	r1, [r11, #-44]	; 0x2c
0x000082a8 <+24>:	ldr	r3, [r11, #-40]	; 0x28
0x000082ac <+28>:	cmp	r3, #1
0x000082b0 <+32>:	bgt	0x82c0 <main+48>
0x000082b4 <+36>:	mvn	r3, #0
0x000082b8 <+40>:	str	r3, [r11, #-48]	; 0x30
0x000082bc <+44>:	b	0x8448 <main+440>
```
This code block is the **main** function prolog. Basically, it checks if any program arguments where given - if not it will jump to the address _main+440_, we seems like the function epilogue.
Let's continue to the address _main+48_, to the next block:
```asm
0x000082c0 <+48>:	mov	r3, #0
0x000082c4 <+52>:	str	r3, [r11, #-28]
0x000082c8 <+56>:	mov	r0, #32
0x000082cc <+60>:	bl	0x8248 <xmalloc>
```

The first 2 instructions, initiates a local variable (in the stack) to 0. Next it will _xmalloc_ a buffer of 32 bytes.<br>
_xmalloc_ is the as _malloc_, but _xmalloc_ acts likes do or die. If it succeed to allocate memory for the buffer then the program will continue. Otherwise, it will terminate it.

```asm
0x000082d0 <+64>:	mov	r3, r0
0x000082d4 <+68>:	str	r3, [r11, #-32]
0x000082d8 <+72>:	b	0x832c <main+156>
```
In this block, the allocated address (the return value of _xmalloc_) will be stored in a local variable, at **fp-32**, and will jump to the address _main+156_.<br>
Now, there is the following loop (where the start address is _main+156_):
```asm
0x000082dc <+76>:	ldr	r3, [r11, #-28]
0x000082e0 <+80>:	lsl	r2, r3, #2
0x000082e4 <+84>:	ldr	r3, [r11, #-32]
0x000082e8 <+88>:	add	r4, r3, r2
0x000082ec <+92>:	mov	r0, #32
0x000082f0 <+96>:	bl	0x8248 <xmalloc>
0x000082f4 <+100>:	mov	r3, r0
0x000082f8 <+104>:	str	r3, [r4]
0x000082fc <+108>:	ldr	r3, [r11, #-28]
0x00008300 <+112>:	lsl	r2, r3, #2
0x00008304 <+116>:	ldr	r3, [r11, #-32]
0x00008308 <+120>:	add	r3, r3, r2
0x0000830c <+124>:	ldr	r3, [r3]
0x00008310 <+128>:	mov	r0, r3
0x00008314 <+132>:	mov	r1, #10
0x00008318 <+136>:	mov	r2, #32
0x0000831c <+140>:	bl	0x11fe0 <memset>
0x00008320 <+144>:	ldr	r3, [r11, #-28]
0x00008324 <+148>:	add	r3, r3, #1
0x00008328 <+152>:	str	r3, [r11, #-28]
0x0000832c <+156>:	ldr	r3, [r11, #-28]  ; <-------------- STARTING HERE
0x00008330 <+160>:	cmp	r3, #8
0x00008334 <+164>:	bne	0x82dc <main+76>
```
The local variable at **fp-28** (reminder - equals to 0) is compared to 8. If it less than 8, the loop will continue. Otherwise, it will exit the loop. In each iteration, a 32 bytes buffer will be allocated, its values will be set to '\n' (0x0a) and will be inserted into the local variable **fp-32**.<br>
So, basically the loop will create a 2-dimensional array of 32x32, which each cell is '\n'.<br>
Doesn't seem too important. So let's continue.<br>

```asm
0x00008338 <+168>:	ldr	r3, [r11, #-28]
0x0000833c <+172>:	lsl	r2, r3, #2
0x00008340 <+176>:	ldr	r3, [r11, #-32]
0x00008344 <+180>:	add	r2, r3, r2
0x00008348 <+184>:	mov	r3, #0
0x0000834c <+188>:	str	r3, [r2]
0x00008350 <+192>:	mov	r3, #0
0x00008354 <+196>:	str	r3, [r11, #-28]
0x00008358 <+200>:	mov	r3, #65	; 0x41
0x0000835c <+204>:	str	r3, [r11, #-24]
0x00008360 <+208>:	b	0x839c <main+268>
```
In this block, the first 6 instructions basically does ```fp-32[32] = 0```.<br>
The next 2 instructions (main+192 and main+196) does ```fp-28=0```.<br>
At the last 3 instructions, ```fp-24=0x41``` and a jump will occur (apparently to another loop).<br>

```asm
0x00008364 <+212>:	ldr	r3, [r11, #-32]
0x00008368 <+216>:	add	r3, r3, #12
0x0000836c <+220>:	ldr	r2, [r3]
0x00008370 <+224>:	ldr	r3, [r11, #-28]
0x00008374 <+228>:	add	r2, r2, r3
0x00008378 <+232>:	ldr	r3, [r11, #-24]
0x0000837c <+236>:	and	r3, r3, #255	; 0xff
0x00008380 <+240>:	strb	r3, [r2]
0x00008384 <+244>:	ldr	r3, [r11, #-24]
0x00008388 <+248>:	add	r3, r3, #1
0x0000838c <+252>:	str	r3, [r11, #-24]
0x00008390 <+256>:	ldr	r3, [r11, #-28]
0x00008394 <+260>:	add	r3, r3, #1
0x00008398 <+264>:	str	r3, [r11, #-28]
0x0000839c <+268>:	ldr	r3, [r11, #-28]  ; <-------------- STARTING HERE
0x000083a0 <+272>:	cmp	r3, #31
0x000083a4 <+276>:	bne	0x8364 <main+212>
```
The loop's condition is ```fp-28 != 31```, and in each iteration the following stuff happen:
<ol>
  <li>The **fp-24** is stored somewhere in the **fp-32** array ((**fp-32**) + 12 + **fp-28** to be exact).</li>
  <li>The **fp-24** value is increased by 1.</li>
  <li>The **fp-28** value is increased by 1.</li>
</ol>

So, basically the string 'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_' is stored somewhere (not that important in my opinion) in **fp-32**.<br>


