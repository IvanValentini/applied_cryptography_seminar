#!/usr/bin/env python3

import os
import socketserver
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

TIMEOUT = 300
BLOCK_SIZE = 16

flag = "SEMINAR{here_is_my_exception_what_could_go_wrong?}"


key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.send(b"Hello! Here's an encrypted flag\n")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        self.request.send((iv.hex()+cipher.encrypt(pad(flag.encode(), BLOCK_SIZE)).hex() + "\n").encode())
        while True:
            try:
                self.request.send(b"What do you want to decrypt (in hex)?\n")
                dec = bytes.fromhex(self.request.recv(1024).strip().decode())
                cipher = AES.new(key, AES.MODE_CBC, dec[:BLOCK_SIZE])
                decrypted = cipher.decrypt(dec[BLOCK_SIZE:])
                decrypted_and_unpadded = unpad(decrypted, BLOCK_SIZE)
                self.request.send(b"Wow you are so strong at decrypting!\n")
            except Exception as e:
                self.request.send((e.args[0]+"\n").encode())


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 1337

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()