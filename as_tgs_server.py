import socket
import json
import time
import os
from datetime import datetime
from Crypto.Cipher import DES

class AS_TGS_Server:
    def __init__(self):
        # Server configuration
        self.host = 'localhost'
        self.port = 9002
        
        # Pre-defined keys (8 bytes for DES)
        self.Kc = b'KC_KEY12'  # Key between Client and AS
        self.Ktgs = b'KT_KEY12'  # Key between AS and TGS
        
        self.IDc = "CIS3319USERID"
        self.IDtgs = "CIS3319TGSID"
        
        unix_epoch_time = int(time.time())
        print(f"Current Unix Epoch Time: {unix_epoch_time}")

        # Initialize server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
    

    def generate_Ticket(self, IDc, IDtgs, client_addr):
        import random
        
        # Generate session key Kc,tgs (16 bytes as specified)
        Kc_tgs = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Create ticket timestamp and lifetime
        TS2 = int(time.time())
        lifetime = 60  # Ticket valid for 60 seconds
        
        # Create the ticket structure to send back to client
        ticket_data = {
            "IDc": IDc,
            "IDtgs": IDtgs,
            "TS2": TS2,
            "lifetime": lifetime,
            "ADc": client_addr,  # Client network address
            "Kc_tgs": Kc_tgs.hex()  # Session key (converted to hex for JSON)
        }
        
        # Encrypt the ticket with Ktgs (server-to-server key)
        cipher = DES.new(self.Ktgs, DES.MODE_ECB)
        ticket_json = json.dumps(ticket_data)
        
        # Pad plaintext to multiple of 8 bytes (DES block size)
        plaintext = ticket_json.encode()
        padding_length = 8 - (len(plaintext) % 8)
        plaintext += bytes([padding_length] * padding_length)
        
        encrypted_ticket = cipher.encrypt(plaintext)
        
        return encrypted_ticket, Kc_tgs

    def ticket_exchange(Idv, ticket, authenticator):
        ticket_data = {
            "Kc_tgs": 

        }
        pass
    
    def handle_client_ASC(self, client_socket):
        try:
            # Get client address in format "{'localhost':{port}}"
            client_addr = f"{{'localhost':{self.port}}}"
            
            # Receive the request from the client
            request_data = client_socket.recv(1024)
            request = json.loads(request_data.decode())
            
            print(f"\nReceived request from {client_addr}:")
            print(f"  IDc: {request.get('IDc')}")
            print(f"  IDtgs: {request.get('IDtgs')}")
            print(f"  TS1: {request.get('TS1')}")
            
            # Extract request data
            IDc = request.get('IDc')
            IDtgs = request.get('IDtgs')
            TS1 = request.get('TS1')
            
            # Generate ticket and session key
            encrypted_ticket, Kc_tgs = self.generate_Ticket(IDc, IDtgs, client_addr)
            
            # Prep parameters to send back to client
            response_data = {
                "ticket": encrypted_ticket.hex(),  # Encrypted ticket (hex for JSON)
                "Kc_tgs": Kc_tgs.hex()  # Session key for client-TGS communication
            }
            
            # Encrypt the session key with Kc (client's key)
            cipher = DES.new(self.Kc, DES.MODE_ECB)
            response_json = json.dumps(response_data)
            plaintext = response_json.encode()
            
            # Pad plaintext to multiple of 8 bytes (DES block size)
            padding_length = 8 - (len(plaintext) % 8)
            plaintext += bytes([padding_length] * padding_length)
            
            encrypted_response = cipher.encrypt(plaintext)
            
            # Send the response to the client
            client_socket.send(encrypted_response)
            print(f"Sent ticket and session key to {client_addr}")
            
        except json.JSONDecodeError:
            print("Error: Received data is not valid JSON")
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
   

    def handle_client_TGSC(self, client_socket):
        try:
            # Get client address in format "{'localhost':{port}}"
            client_addr = f"{{'localhost':{self.port}}}"
            request_data = client_socket.recv(1024)
            request = json.loads(request_data.decode())

            print(f"\nReceived request from {client_addr}:")
            print(f"  IDv: {request.get('IDv')}")
            print(f"  Ticket: {request.get('ticket')}")
            print(f"  Authenticator: {request.get('authenticator')}")

            IDv = request.get('IDv')
            ticket = request.get('ticket')
            authenticator = request.get('authenticator')

            
        except Exception as e:
            print(f"Error handling TGS client: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        self.server_socket.listen(5)
        print(f"AS/TGS Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr} has been established.")
            self.handle_client_ASC(client_socket)
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr} has been established.")
            self.handle_client_ASC(client_socket)


if __name__ == "__main__":
    server = AS_TGS_Server()
    server.start()
