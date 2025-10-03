from Crypto.Util.strxor import strxor

with open("ciphertext1.enc", 'rb') as f:
    c1 = f.read()

with open("ciphertext2.enc", 'rb') as f:
    c2 = f.read()


k = strxor(c1,c2)
# s = b"cs409{one_time_pad_key_reuse_compromises_security" + b"\x00" * (len(k) - len(b"cs409{one_time_pad_key_reuse_compromises_security"))
s = b"Cryptanalysis frequently involves statistical attack." + b"\x00" * (len(k) - 53)
# s = b"Cryptanalysis frequently involves statistical attempts" + b"\x00" * (len(k) - len(b"Cryptanalysis frequently involves statistical attempts"))



# print(k,len(k))
print(len(s))
print(strxor(k,s))

