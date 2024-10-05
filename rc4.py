from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes

def encrypt(key, plaintext):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt(key, ciphertext):
    cipher = ARC4.new(key)
    plaintext = cipher.encrypt(ciphertext)
    return plaintext

def generate_key(length):
    key = get_random_bytes(length)
    return key

def main():
    plaintext = bytes(input("Plaintext: "), encoding='UTF-8')

    key = generate_key(16)
    ciphertext = encrypt(key, plaintext)
    decrypted_ciphertext = decrypt(key, ciphertext)

    print(f'Key: {key}')
    print(f'Plaintext: {plaintext}')
    print(f'Ciphertext: {ciphertext}')
    print(f'Decrypted ciphertext: {decrypted_ciphertext}')

if __name__ == '__main__':
	main()