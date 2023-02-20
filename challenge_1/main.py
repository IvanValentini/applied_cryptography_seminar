#!/usr/bin/env python3

import socketserver
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad

FLAG="SEMINAR{your_ciphertext_counts}"
key = os.urandom(16)


def CTR(pt):
    counter = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    ct = cipher.encrypt(pad(pt, 16))
    return ct

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # self.request is the TCP socket connected to the client
        while True:
            self.request.send(b"\nOptions:\n\n1.Encrypt flag\n2.Encrypt plaintext\n3.Exit\n\n>")
            option = self.request.recv(1024).strip().decode()
            
            if option == "1":
                ciphertext = CTR(FLAG.encode()).hex()
                self.request.send(ciphertext.encode())
            elif option == "2":
                self.request.send(b"Enter plaintext: \n")
                plaintext = self.request.recv(1024).strip()
                ciphertext = CTR(plaintext).hex()
                self.request.send(ciphertext.encode())
            elif option == "3":
                self.request.send(b"Bye bye\n")
                break
            else:
                self.request.send(b"Unrecognized command " + option.encode())

if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 1337

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()