
import socket
import json
import time
from datetime import datetime
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
        msg_bytes = self.s.recv(self.buffer_size)

        return msg_bytes

    def close(self):
        self.s.close()


if __name__ == '__main__':
    # Connect to Authentication Server (AS)
    client = Client('localhost', 9002)  # AS server port
    
    # Define client and TGS IDs as specified
    IDc = "CIS3319USERID"
    IDtgs = "CIS3319TGSID"
    IDv = "CIS3319SERVERID"
    lifetime = 60 # 60 seconds
    
    try:
        # Create timestamp for request freshness (Unix/Epoch time in seconds)
        timestamp = int(time.time())  # Current time in seconds since epoch
        
        # Create the request message for AS
        as_request = {
            "IDc": IDc,           # Client ID
            "IDtgs": IDtgs,       # ID of the TGS we want to access
            "TS1": timestamp      # Timestamp for freshness (Unix time)
        }

        # Send the request to AS
        client.send(json.dumps(as_request).encode())
        print(f"Sent AS request: {as_request}")
        
        # Receive the response from the AS server
        encrypted_response = client.recv()
        print(f"\nReceived encrypted response from AS")
        
        # Decrypt the response using Kc
        cipher = DES.new(client.Kc, DES.MODE_ECB)
        decrypted_plaintext = cipher.decrypt(encrypted_response)
        
        # Remove padding that was added during encryption - found solution to remove this padding online
        padding_length = decrypted_plaintext[-1]
        decrypted_plaintext = decrypted_plaintext[:-padding_length]
        
        # Parse the JSON response
        response = json.loads(decrypted_plaintext.decode())

        print(f"\nDecrypted outer response:")
        print(f"  Ticket for TGS (hex): {response.get('ticket_tgs')[:50]}...")
        print(f"  Encrypted inner payload (hex): {response.get('enc_with_kc_tgs')[:50]}...")
        print(f"  Session Key Kc,tgs (hex): {response.get('Kc_tgs')}")

        # Store the session key for later use with TGS
        Kc_tgs = bytes.fromhex(response.get('Kc_tgs'))
        ticket = bytes.fromhex(response.get('ticket_tgs'))

        # Decrypt the inner payload using Kc_tgs (use first 8 bytes for DES)
        encrypted_inner = bytes.fromhex(response.get('enc_with_kc_tgs'))
        cipher_inner = DES.new(Kc_tgs[:8], DES.MODE_ECB)
        decrypted_inner = cipher_inner.decrypt(encrypted_inner)
        padding_len_inner = decrypted_inner[-1]
        decrypted_inner = decrypted_inner[:-padding_len_inner]
        inner = json.loads(decrypted_inner.decode())

        print(f"\nDecrypted inner payload:")
        print(f"  Kc_v (hex): {inner.get('Kc_v')}")
        print(f"  Ticket_v (hex): {inner.get('ticket_v')[:50]}...")
        print(f"  IDv: {inner.get('IDv')}")
        print(f"  TS4: {inner.get('TS4')}")

        Kc_v = bytes.fromhex(inner.get('Kc_v'))
        ticket_v = bytes.fromhex(inner.get('ticket_v'))

        print(f"\nReceived session keys and tickets successfully.")

        as_request = {
            "IDv": IDv,           # Client IDv
            "ticket": ticket.hex(), # Ticket for TGS (converted to hex for JSON)
            "authenticator": {
                "IDc": IDc,
                "TS3": int(time.time())
            }
        }

        # Send the request to TGS
        client.send(json.dumps(as_request).encode())
        print(f"\nSent TGS request: {as_request}")
    except json.JSONDecodeError as e:
        print(f"Error decoding response: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()
        print("\nConnection closed")
