import hashlib

def group_sub(m1: bytes, m2: bytes) -> bytes:
    assert len(m1) == len(m2)
    res = b""
    for i in range(len(m1)):
        res += chr((m1[i] - m2[i]) % 128).encode()
    return res

def generate_key(first_byte: int, length: int) -> bytes:
    key = chr(first_byte).encode()
    for _ in range(1, length):
        key += chr(hashlib.sha256(key).digest()[0] % 128).encode()
    return key

with open("ciphertext.enc", "rb") as f:
    c = f.read()

for i in range(128):
    key = generate_key(i, len(c))
    plaintext = group_sub(c, key)

    decoded = plaintext.decode()

    if decoded.startswith("cs409{"):
        print(decoded)
