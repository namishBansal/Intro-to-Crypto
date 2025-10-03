from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 19966

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


recvuntil("IV: ")
IV = bytes.fromhex(recvline())

recvuntil("Flag: ")
flag_enc = bytes.fromhex(recvline())


def validate_padding(iv_hex: str, ciphertext_hex: str) -> bool:
    recvuntil("validated:\n")
    sendline(ciphertext_hex)
    recvuntil("IV:\n")
    sendline(iv_hex)
    response = recvline()
    valid_padding = ("Valid Padding!" in response)
    return valid_padding


# ===== YOUR CODE BELOW =====
# The variable IV has the iv (as a bytes object)
# The variable flag_enc has the ciphertext (as a bytes object)
# You can call the function validate_padding(iv_hex: str, ciphertext_hex: str) -> bool which takes in the hex of the iv (str) and hex of the ciphertext (str) and returns True if the corresponding plaintext has valid padding, and return False otherwise (as dictated by the server's response)

blocks = [flag_enc.hex()[i:i+32] for i in range(0,len(flag_enc.hex()),32)]

C_dash = "0"*32
C_dash_bytes = bytes.fromhex(C_dash)
print(flag_enc)
C1 = blocks[0]
C1_bytes = bytes.fromhex(C1)
P2 = "0"*32
P2_bytes = bytes.fromhex(P2)

for pad in range(1,17):
    C1_bytes = bytearray(C1_bytes)
    C_dash_bytes = bytearray(C_dash_bytes)
    P2_bytes = bytearray(P2_bytes)
    for j in range(1,pad):
        C_dash_bytes[16-j] = pad ^ P2_bytes[16-j] ^ C1_bytes[16-j]
    
    for guess in range(0,255):
        C_dash_bytes[16-pad] = guess

        if validate_padding(C_dash_bytes.hex(),blocks[1]):
            P2_bytes[16-pad] = pad ^ C1_bytes[16-pad] ^ guess
            print(P2_bytes)
            break

C_dash = "0"*32
C_dash_bytes = bytes.fromhex(C_dash)
# print(flag_enc)
C1 = IV.hex()
C1_bytes = bytes.fromhex(C1)
P1 = "0"*32
P1_bytes = bytes.fromhex(P2)

for pad in range(1,17):
    C1_bytes = bytearray(C1_bytes)
    C_dash_bytes = bytearray(C_dash_bytes)
    P1_bytes = bytearray(P1_bytes)
    for j in range(1,pad):
        C_dash_bytes[16-j] = pad ^ P1_bytes[16-j] ^ C1_bytes[16-j]
    
    for guess in range(0,255):
        C_dash_bytes[16-pad] = guess

        if validate_padding(C_dash_bytes.hex(),blocks[1]):
            P1_bytes[16-pad] = pad ^ C1_bytes[16-pad] ^ guess
            print(P1_bytes)
            break

print(P1_bytes)
print(P2_bytes)
# print(IV)



# ===== YOUR CODE BELOW =====

target.close()
