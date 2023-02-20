#!/usr/bin/env python3

from pwn import *
p = remote("127.0.0.1",1337)

# Register a user with username 'a'
p.sendlineafter(b">",b"1")
name = "a"
p.sendlineafter(b":",name.encode())

# Read the login token
token = p.recvline().decode().split(": ")[1]

# Extract the IV part of the token
iv = bytes.fromhex(token[:32])
cookie = f"usr={name};is_admin=0".encode()
pt_xor_iv = xor(cookie,iv) # Calculate (1)

# Calculate the new IV, such that pt_xor_iv xor new_iv = "usr=a;is_admin=1"
new_iv = xor(pt_xor_iv,b"usr=a;is_admin=1")
new_iv_hex = new_iv.hex().encode()
new_token = new_iv_hex + token[32:].encode()

# Send the cookie with the newly crafted IV
p.sendlineafter(b">",b"2")
p.sendlineafter(b":",new_token)

# Receive the flag
print(p.recvline())
print(p.recvline())

# Exit command
p.sendlineafter(b">",b"0")
p.close()