from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# initiate 16 byte key for aes and iv because we use CBC mode
key = get_random_bytes(16) 
iv = get_random_bytes(16)

# inititate encryptor
aes = AES.new(key, AES.MODE_CBC, iv)

plaintext = b'imLearningEncryptionNow'

# add padding to fullfil the block size
# encode to b64 for easier storing
ciphertext = b64encode(aes.encrypt(pad(plaintext, AES.block_size))).decode('utf-8')
print("Ciphertext:",ciphertext)

# initiate decryptor
aes = AES.new(key, AES.MODE_CBC, iv)

# decrypt the ciphertext
plaintext = unpad(aes.decrypt(b64decode(ciphertext)), AES.block_size).decode('utf-8')
print("Plaintext: ",plaintext)