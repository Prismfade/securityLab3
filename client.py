import socket
import json
import time
from Crypto.Cipher import DES

class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size
        # Pre-defined key shared with AS (8 bytes for DES)
        self.Kc = b'KC_KEY12'  # Key between Client and AS

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.addr, self.port))

    def send(self, msg_bytes: bytes):
        self.s.send(msg_bytes)

    def recv(self, buffer_size=None) -> bytes:
        if buffer_size is None:
            buffer_size = self.buffer_size
        msg_bytes = self.s.recv(buffer_size)
        return msg_bytes

    def close(self):
        self.s.close()


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


if __name__ == "__main__":
    IDc = "CIS3319USERID"
    IDtgs = "CIS3319TGSID"
    IDv = "CIS3319SERVERID"

    #  1: AS REQUEST
    print("\n=== PHASE 1: Requesting TGS Ticket from AS ===")

    client = Client("localhost", 9009)

    TS1 = int(time.time())
    as_request = {
        "IDc": IDc,
        "IDtgs": IDtgs,
        "TS1": TS1
    }

    client.send(json.dumps(as_request).encode())
    print("Sent AS request:", as_request)

    encrypted_response = client.recv(4096)
    cipher = DES.new(client.Kc, DES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_response)
    decrypted = unpad(decrypted)

    as_reply = json.loads(decrypted.decode())
    ticket_tgs_hex = as_reply["ticket"]
    print("Received Tickettgs (hex):", ticket_tgs_hex[:80], "...")

    # Important: Close AS connection
    client.close()

    #  2: TGS REQUEST
    print("\n=== PHASE 2: Requesting Ticket_v from TGS ===")

    client = Client("localhost", 9009)

    tgs_request = {
        "IDv": IDv,
        "Tickettgs": ticket_tgs_hex,
        "authenticator": {
            "IDc": IDc,
            "ADc": "{'localhost':9001}",
            "TS3": int(time.time())
        }
    }

    client.send(json.dumps(tgs_request).encode())
    print("Sent TGS request:", tgs_request)

    tgs_reply_bytes = client.recv(4096)
    tgs_reply = json.loads(tgs_reply_bytes.decode())

    print("\n--- TGS Response ---")
    print("Ticketv:", tgs_reply["Ticketv"][:80], "...")
    print("Kcv:", tgs_reply["Kcv"][:80], "...")
    print("IDv:", tgs_reply["IDv"])
    print("TS4:", tgs_reply["TS4"])

    cv_request = {
        "Ticketv": tgs_reply["Ticketv"],
        "authenticator": {
            "IDc": IDc,
            "ADc": "{'localhost':9001}",
            "TS5": int(time.time())
        }
    }

    client.close()
