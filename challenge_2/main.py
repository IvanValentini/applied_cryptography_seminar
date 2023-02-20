#!/usr/bin/env python3

import signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import socketserver

TIMEOUT = 300

flag = "SEMINAR{I_m_the_admin_now}"

key = os.urandom(16)

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            self.request.send(b"1. Register\n2. Login\n0. Exit\n>")
            choice = self.request.recv(1024).strip().decode()
            choice = int(choice)
            if choice == 1:
                self.request.send(b"Insert your username: ")
                name = self.request.recv(1024).strip().decode()
                
                if ";" in name:
                    continue
                cookie = f"usr={name};is_admin=0".encode()
                iv = os.urandom(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(cookie, 16))

                self.request.send(f"Your login token: {iv.hex()+encrypted.hex()}\n".encode())
            elif choice == 2:
                self.request.send(b"Insert your token: ")
                token = self.request.recv(1024).strip().decode()
                
                try:
                    cookie = bytes.fromhex(token[32:])
                    iv = bytes.fromhex(token[:32])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(cookie),16)
                    values = pt.split(b";")
                    user = values[0].split(b"=")[-1].decode()
                    self.request.send(f"Welcome back {user} {values[1].decode()}\n".encode())
                    if b"is_admin=1" in values:
                        self.request.send(f"Here is your flag {flag}\n".encode())
                except:
                    self.request.send(b"Something is wrong with your token.\n")


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 1337

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()