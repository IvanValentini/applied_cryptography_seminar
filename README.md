# Environment creation

We are creating an environment to avoid pulluting your system.

PyCryptodome is a self-contained Python package of low-level cryptographic primitives.
pwntools is a CTF framework and exploit development library. It allows us to automate the finding of the solutions for the three challenges by interacting with the challenges. 

In a Linux environemnt:
```bash
python -v venv venv
source venv/bin/activate
pip install pycryptodome pwntools
```

In a Windows environment:
```powershell
python -v venv venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\venv\Scripts\activate
pip install pycryptodome pwntools
```

# Solutions

Solutions are provided. You are advised to try out the challenges before reading the solution. Solutions have been tested in a Linux and Windows machine with Python3.8 .

# Interacting with the server

You can use pwntools to interact with the server. To connect simply:
```python
from pwn import *
p = remote("127.0.0.1",1337)
```

To send some bytes to the server after a some bytes have been received:
```python
from pwn import *
p = remote("127.0.0.1",1337)
p.sendlineafter(b": ",b"abc")
```

This is useful for answering to propts such as: "Insert your username: ".

To receive the server answer you can:
```python
from pwn import *
p = remote("127.0.0.1",1337)
print(p.recvline())
```

To convert from hex to bytes and viceversa you can:
```python
print(b"A".hex())          # Will print "41"
print(bytes.fromhex("41")) # Will print b"A"
```

