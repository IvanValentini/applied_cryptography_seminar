#!/usr/bin/env python3

from pwn import *
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16
    
def decrypt(IV, C1_prime, C2):
    C1_prime = b"".join(C1_prime)
    ct = IV.hex() + C1_prime.hex() + C2.hex()
    p.sendlineafter(b"?\n",ct.encode())
    return p.recvline().strip()

p = remote("127.0.0.1",1337)

p.recvline()
msg_enc = bytearray.fromhex(p.recvline().strip().decode())
IV = msg_enc[:BLOCK_SIZE]
flag_enc = msg_enc[BLOCK_SIZE:]

# Prepare a list of blocks to decrypt, containing the "real" bytes
# We will add also the IV so that we can also decrypt the first block
blocks = [IV]
for i in range(0,len(flag_enc),BLOCK_SIZE):
    blocks.append(flag_enc[i:i+BLOCK_SIZE])

# This will contain the decrypted flag
pt = b""

# Implementation of https://robertheaton.com/2013/07/29/padding-oracle-attack/
# Begin from the end
for l in range(len(blocks)-1,0,-1):

    # The block we are trying to decrypt, C2
    C2 = blocks[l] # The block we are trying to decrypt, C2

    # Initalize the itermediate state I2
    I2 = [b"\x00" for i in range(BLOCK_SIZE)]
    
    # The block that will help us in the decryption, C1
    C1_prime = [os.urandom(1) for k in range(BLOCK_SIZE)] 

    # Manipulate each byte of the block C1 starting from the end
    for i in range(BLOCK_SIZE-1,-1,-1):

        # Adjust C1 such that the padding is correct
        # This will be used after last byte of C2 is decrypted
        for k in range(i+1,BLOCK_SIZE):
            C1_prime[k] = xor(bytes([BLOCK_SIZE-i]),I2[k])
        
        # Try every possible value of the i-th byte of C1 until a valid padding is found
        for j in range(0,255):

            # Update the i-th byte of C1
            C1_prime[i] = bytes([j])

            # Attempt to decrypt with the modified C1 and C2
            decryption_result = decrypt(IV,C1_prime,C2)

            if b"Wow you are so strong at decrypting!" in decryption_result:
                # Padding is correct, we have succesfully decrypted a byte

                # Calculate the i-th byte of the intermediate state
                I2[i] = xor(bytes([j]),bytes([BLOCK_SIZE-i]))

                # Calculate the decrypted byte
                p2 = xor(blocks[l-1][i],I2[i])

                # Append the decrypted byte to the decrypted plaintext
                pt = p2 + pt

                break

        print(pt)

log.success(unpad(pt,16).decode())
p.close()