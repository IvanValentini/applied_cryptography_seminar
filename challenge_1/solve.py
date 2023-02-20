#!/usr/bin/env python3

from pwn import *
p = remote("127.0.0.1",1337)

# Step 1: Get the encrypted flag
p.sendlineafter(b">",b"1")
enc_flag_hex = p.recvline().decode() # Receive enc(flag)
print("Encrypted flag: " + enc_flag_hex)

enc_flag = bytes.fromhex(enc_flag_hex)

# Step 2: Encrypt the plaintext
pt = b"A"*len(enc_flag)
p.sendlineafter(b">",b"2")
p.sendlineafter(b": \n",pt) # Send the plaintext
enc_pt_hex = p.recvline().decode() # Receive enc(pt)
enc_pt = bytes.fromhex(enc_pt_hex)

# Step 3: Get the flag 
k = xor(enc_pt,pt)
flag = xor(enc_flag,k)

print(flag)

p.close()