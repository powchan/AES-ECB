from pwn import process, context
from Crypto.Cipher import AES
from random import randint
context(os='linux', arch='amd64', log_level='debug')
io = process("./main")

count = 10
for i in range(count):

    key = randint(1<<120-1, 1<<128-1).to_bytes(16, "big")
    mytext = randint(1<<120-1, 1<<128-1).to_bytes(16, "big")
    mode = str(randint(2, 2)).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    if (mode == b"1"):
        res = cipher.encrypt(mytext)
    else:
        res = cipher.decrypt(mytext)
    io.recvuntil(b'0: exit\n')
    io.sendline(mode)
    io.sendline(key)
    io.sendline(mytext)
    io.recvuntil(b"Result: ")
    
    ret = io.recv(16)
    print(ret)
    if  ret != res:
        print(f"The {i+1}th test is failed!")
        print(f"mode={mode.decode()}\tkey={key.hex()}\ttext={mytext.hex()}")
        print(f"return  res={ret.hex()}\ncorrect res={res.hex()}")
        exit(1)
    else:
        if (mode == b"1"):
            modestr = "encrypt"
        else:
            modestr = "decrypt"
        print(f"The {i+1}th test is passed!\t Mode:"+modestr)
print("Passed tests!")