with open("ciphertext (1).enc", 'rb') as f:
    c1 = f.read()

with open("keyfile",'rb') as f:
    key = f.read()

def bytes_255 (s):
    num = int.from_bytes(s,"big")

    digits =[]
    while num>0:
        digits.append(num%255)
        num //= 255

    return digits[::-1]

def b255_bytes (s):
    num=0
    for d in s:
        num = num*255 + d

    return num.to_bytes((num.bit_length() + 7) // 8, "big")

l = len(key)
c_255 = bytes_255(c1)
p_255 = [((c-k+1)%255) for c,k in zip(c_255,key)]
flag = b255_bytes(p_255)
print(flag)