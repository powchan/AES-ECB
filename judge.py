from pwn import *
from Crypto.Cipher import AES
from random import randint
context(os='linux', arch='amd64', log_level='debug')
try:
    io = process("./main")
except:
    os.system("gcc main.c -o main")
    io = process("./main")

count = int(input("Enter the number of test runs: "))
for i in range(count):
    print(i)
    key = randint(0, 1<<128-1).to_bytes(16, "big")
    mytext = randint(0, 1<<128-1).to_bytes(16, "big")
    mode = str(randint(1, 2)).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    if (mode == b"1"):
        res = cipher.encrypt(mytext)
    else:
        res = cipher.decrypt(mytext)
    io.sendline(mode)
    io.sendline(key)
    io.sendline(mytext)
    io.recvuntil(b"Result: ")
    
    ret = io.recvuntil(b"\n")[2:-1]
    if  ret != res:
        print(f"The {count}th test is failed!")
        print(f"mode={mode.decode()}\tkey={key.hex()}\ttext={mytext.hex()}")
        print(f"return  res={ret.hex()}\ncorrect res={res.hex()}")
        exit(1)
    else:
        if (mode == b"1"):
            mode = "encrypt"
        else:
            mode = "decrypt"
        print(f"The {i+1}th test is passed!\t Mode:"+mode)
print("Passed tests!")