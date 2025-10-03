HEADER = "_Have you heard about the \{quick\} brown fox which jumps over the lazy dog?\n__The decimal number system uses the digits 0123456789!\n___The flag is: "


if __name__ == '__main__':
    with open("ciphertext.bin", "rb") as f:
        ct = f.read()
    blocks=[ct[i:i+16] for i in range(0,len(ct),16)]
    lenh = len(HEADER)

    head_blocks = blocks[:lenh]
    flag_blocks = blocks[lenh:]

    dict_blk ={}
    for blk,ch in zip(head_blocks,HEADER):
        dict_blk[blk]=ch

    flag_chars = []
    for blk in flag_blocks:
        flag_chars.append(dict_blk[blk])

    flag = ''.join(flag_chars)

    print(flag)

