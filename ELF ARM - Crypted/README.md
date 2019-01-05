# ELF ARM - Crypted
https://www.root-me.org/en/Challenges/Cracking/ELF-Crypto-ARM
```
Indentify the cryptographic algorithm used to be able to find back the flag (tested on Android 2.2).
```

The output of ```arm-linux-gnueabihf-objdump -D cryptoarm``` is ```cryptoarm:     file format elf32-littlearm```.<br>
This mean that the executable is probably packed. So let's try to find some clues about the packer.<br>
After running the ```strings cryptoarm```, the following strings came to my eye: 
```
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
```

Ok. So the UPX packet was used.<br>
After downloading it (no installation needed), and after unpacking the executable using the command ```./upx -d cryptarm```, it seems that the ```arm-linux-gnueabihf-objdump -D cryptoarm``` could disassemble the executable correctly.<br>
Now it's possible to reverse it (statically or just debugging it).<br><br>

[To be continued]
