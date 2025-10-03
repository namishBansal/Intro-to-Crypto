openssl enc -d -aes-128-cbc -in ciphertext.bin -K $(cat key.hex) -iv $(cat iv.hex)
