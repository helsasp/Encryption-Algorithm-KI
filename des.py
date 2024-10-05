from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# inititate DES key and IV because we use CBC mode
key = get_random_bytes(8)
iv = get_random_bytes(8)

# initialize encryptor
cipher = DES.new(key, DES.MODE_CBC, iv)

# add padding to fullfil the block size
plaintext = b"ireallyamtrying"
ciphertext = b64encode(cipher.encrypt(pad(plaintext, DES.block_size))).decode('utf-8')

print(f"Ciphertext: {ciphertext}")

# initialize decryptor
cipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_data = unpad(cipher.decrypt(b64decode(ciphertext)), DES.block_size).decode('utf-8')

print(f"Plaintext: {decrypted_data}")