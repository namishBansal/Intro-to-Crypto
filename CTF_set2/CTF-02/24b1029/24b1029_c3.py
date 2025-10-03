from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 11437

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python3", "./server.py"])
target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp)
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp)
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp)
    return resp

def choice1(params: str) -> str:
    recvuntil("parameters: ")
    sendline("1")
    recvuntil("parameters: ")
    sendline(params)
    recvuntil("hex): ")
    ciphertext_hex = recvline().strip()
    return ciphertext_hex

def choice2(params_enc: str) -> tuple[bool, str]:
    recvuntil("parameters: ")
    sendline("2")
    recvuntil("hex): ")
    sendline(params_enc)
    resp = recvline().strip()
    if resp == "Invalid parameters! Incorrect padding or Non-ASCII characters detected!":
        recvuntil("hex): ")
        return False, recvline().strip()
    elif resp == "Your parameters have been successfully submitted!":
        return False, ""
    elif resp == "Welcome, admin!":
        recvuntil("flag: ")
        return True, recvline().strip()
        


# ===== YOUR CODE BELOW =====
# Use the function choice1(params) the send your parameters (str) to the server (Choice 1)
# It returns (given that your input was successfully processed) the ciphertext as a hex-string
#
# Use the function choice2(params_enc) to send your encrypted parameters (hex string) to the server (Choice 2)
# It returns a 2-tuple: the first component being a boolean indicating whether you got admin access (True) or not (False), the second component being the hex-string returned by the server (empty string in the case that the server returns nothing)

inp = "\x00"*16 + '='
cipher = choice1(inp)
cipher = cipher[:32]
inp2 = cipher + "00"*16
inp2 = inp2+ cipher
out = choice2(inp2)
pj = out[1][64:]
# print (len(pj))
key = bytes.fromhex(pj)
# print(key)
inp = "admin=true".encode()
cipher = AES.new(key, AES.MODE_CBC, iv=key)
ciphertext = cipher.encrypt(pad(inp, AES.block_size)).hex()
out_ = choice2(ciphertext)
# print(out_[1])
cipher1 = AES.new(key, AES.MODE_CBC, iv=key)

params_padded = cipher1.decrypt(bytes.fromhex(out_[1]))
print(unpad(params_padded,16).decode())
# ===== YOUR CODE ABOVE =====

try:
    target.close()
except:
    pass
