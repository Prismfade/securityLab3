
import random

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES:
    """
    A simple AES ECB wrapper for encryption and decryption.
    Padding is handled by adding null bytes to the end of the plaintext.
    Trailing whitespace in messages is removed after decryption.
    """

    def __init__(self, key: bytes):
        self.key = key
        self.key_len = len(key) * 8

        self.cipher = Cipher(algorithms.AES(key), modes.ECB())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def encrypt(self, plaintext: str) -> bytes:
        plaintext_bytes = bytes(plaintext, 'ascii')
        # padding
        block_size = self.key_len // 8
        plaintext_bytes += b'\x00' * (block_size - len(plaintext_bytes) % block_size)
        return self.encryptor.update(plaintext_bytes) + self.encryptor.finalize()
    
    def decrypt(self, ciphertext: bytes) -> str:
        decrypted_bytes = self.decryptor.update(ciphertext) + self.decryptor.finalize()
        # decrypted = bytes.decode(decrypted_bytes, 'ascii')
        decrypted = bytes.decode(decrypted_bytes, 'ascii').rstrip('\x00')
        return decrypted



if __name__ == '__main__':

    # use a random key
    key_len = 256
    key = bytes([random.randint(0, 255) for _ in range(key_len // 8)])
    
    # instantiate an AES cryptor
    # now you can encrypt and decrypt messages
    cryptor = AES(key)

    # your custom plaintext message
    plaintext = "Hello! I am Justin"
    # encrypt
    ciphertext = cryptor.encrypt(plaintext)
    # decrypt
    decrypted = cryptor.decrypt(ciphertext)

    # check if everything works
    print(f"plaintext: {plaintext}")
    # typically unreadable, but we can print it as hex
    print(f"ciphertext: {ciphertext.hex()}")
    # check decrypted message
    print(f"decrypted: {decrypted}")
    # report if there is something wrong
    assert plaintext == decrypted, "Incorrect decryption!"

    # check the SHA256 of the ciphertext
    digest = hashes.Hash(hashes.SHA256())
    digest.update(ciphertext) 
    hmac = digest.finalize()
    print(f"SHA256 of ciphertext: {hmac.hex()}")
    