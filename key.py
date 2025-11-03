
import random


class Key:
    """
    A simple key class that generates, reads, and writes keys.
    """

    def __init__(self,):
        pass

    def gen(self, key_len: int) -> bytes:
        #implemented code
        randomByte = random.randbytes(key_len)
        bytearray(randomByte)
        return bytes([random.randint(0, 255) for _ in range(key_len // 8)])
    
    def read(self, key_file: str) -> bytes:
        with open(key_file, 'rb') as f:
            return f.read()

    def write(self, key: bytes, key_file: str) -> None:
        with open(key_file, 'wb') as f:
            f.write(key)


if __name__ == '__main__':
    key = Key()
    key_len = 256

    # generate a random key
    key_bytes = key.gen(key_len)
    print("Generated key:")
    print(key_bytes.hex())

    # write the key to a file
    key_file = 'key.bytes'
    key.write(key_bytes, key_file)
    print("Key written to file:", key_file)

    # read the key from a file
    key_bytes = key.read(key_file)
    print("Read key from file:", key_file)
    print("Key:")
    print(key_bytes.hex())


