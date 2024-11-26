from pwn import process, context
from Crypto.Cipher import AES
from random import randint
context(os='linux', arch='amd64', log_level='debug')
io = process("./main")

count = 10000
for i in range(count):

    key = randint(0, 1<<128-1).to_bytes(16, "big")
    mytext = randint(0, 1<<128-1).to_bytes(16, "big")
    mode = str(randint(1, 2)).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    if (mode == b"1"):
        res = cipher.encrypt(mytext)
    else:
        res = cipher.decrypt(mytext)
    io.sendline(mode)
    io.send(key)
    io.send(mytext)
    io.recvuntil(b"Result: ")
    def recv_all(io, length):
        data = b""
        while len(data) < length:
            packet = io.recv(length - len(data))
            if not packet:
                # 如果没有更多数据可读，表示连接已关闭
                break
            data += packet
        return data

    ret = recv_all(io, 16)
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