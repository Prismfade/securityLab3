
import socket
import json
import time
from datetime import datetime


class Client:
    def __init__(self, addr, port, buffer_size=1024):
        self.addr = addr
        self.port = port
        self.buffer_size = buffer_size

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
    
    try:
        # Create timestamp for request freshness (Unix/Epoch time in seconds)
        timestamp = int(time.time())  # Current time in seconds since epoch
        
        # Create the request message for AS
        as_request = {
            "IDc": IDc,           # Client ID
            "IDtgs": IDtgs,       # ID of the TGS we want to access
            "TS1": timestamp      # Timestamp for freshness (Unix time)
        }
        
        # Convert request to JSON and then to bytes
        request_bytes = json.dumps(as_request).encode()
        
        # Send request to AS
        print(f"Sending request to AS at Unix time: {timestamp}")
        print(f"Human readable time: {datetime.fromtimestamp(timestamp)}")
        print(f"Client ID: {IDc}")
        print(f"TGS ID: {IDtgs}")
        client.send(request_bytes)
        
        # Wait for AS response
        response = client.recv()
        print("Received response from AS")
        print(response.decode())
        
    finally:
        client.close()
        print("Connection closed")
