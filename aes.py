from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

def get_key(password):
    hasher = SHA256.new(password.encode())
    return hasher.digest()

def pad(data):
    length = 16 - (len(data) % 16)
    return data + bytes([length]) * length

def unpad(data):
    return data[:-data[-1]]

def encrypt(text, password):

    key = get_key(password)
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad(text.encode()))

    return base64.b64encode(iv + encrypted).decode()


def decrypt(token, password):

    key = get_key(password)

    data = base64.b64decode(token)

    iv = data[:16]
    ciphertext = data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(ciphertext)

    return unpad(decrypted).decode()


if __name__ == "__main__":

    mode = input("Encrypt or Decrypt (e/d): ")

    password = input("Password: ")

    if mode == "e":

        text = input("Text: ")
        print("Encrypted:")
        print(encrypt(text, password))

    elif mode == "d":

        token = input("Encrypted text: ")
        print("Decrypted:")
        print(decrypt(token, password))
