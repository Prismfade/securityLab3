import socket
import json
from datetime import datetime
from cryptography.fernet import Fernet

class AS_TGS_Server:
    def __init__(self):
        # Server configuration
        self.host = 'localhost'
        self.port = 9002
        
        # TGS ID
        self.IDtgs = "CIS3319TGSID"
        
        # Generate key for TGS
        self.tgs_key = Fernet.generate_key()
        self.tgs_cipher = Fernet(self.tgs_key)
        
        # Client database (in real system, this would be securely stored)
        self.client_keys = {
            "CIS3319USERID": Fernet.generate_key()  # Client's key (in real system, derived from password)
        }
        
        # Initialize server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
    
    def verify_timestamp(self, timestamp):
        # Check if timestamp is within acceptable range (e.g., 5 minutes)
        current_time = datetime.now().timestamp()
        return abs(current_time - timestamp) <= 300  # 5 minutes
    
    def handle_client_request(self, client_socket, client_address):
        try:
            # Receive client's request
            request_data = client_socket.recv(4096)
            request = json.loads(request_data.decode())
            
            # Extract request components
            client_id = request.get('IDc')
            requested_tgs = request.get('IDtgs')
            timestamp = request.get('TS1')
            
            print(f"Received request from client {client_id}")
            print(f"Requested TGS: {requested_tgs}")
            print(f"Timestamp: {datetime.fromtimestamp(timestamp)}")
            
            # Verify client ID exists
            if client_id not in self.client_keys:
                error_msg = {"error": "Unknown client"}
                client_socket.send(json.dumps(error_msg).encode())
                return
                
            # Verify TGS ID
            if requested_tgs != self.IDtgs:
                error_msg = {"error": "Invalid TGS ID"}
                client_socket.send(json.dumps(error_msg).encode())
                return
                
            # Verify timestamp freshness
            if not self.verify_timestamp(timestamp):
                error_msg = {"error": "Timestamp expired"}
                client_socket.send(json.dumps(error_msg).encode())
                return
            
            # Generate session key for client-TGS communication
            client_tgs_session_key = Fernet.generate_key()
            
            # Create ticket for TGS
            ticket_tgs = {
                "client_id": client_id,
                "tgs_id": self.IDtgs,
                "timestamp": datetime.now().timestamp(),
                "lifetime": 3600,  # 1 hour lifetime
                "client_tgs_session_key": client_tgs_session_key.decode()
            }
            
            # Encrypt ticket with TGS's key
            encrypted_ticket = self.tgs_cipher.encrypt(json.dumps(ticket_tgs).encode())
            
            # Create message for client, encrypted with client's key
            client_cipher = Fernet(self.client_keys[client_id])
            client_message = {
                "client_tgs_session_key": client_tgs_session_key.decode(),
                "IDtgs": self.IDtgs,
                "timestamp": datetime.now().timestamp(),
                "lifetime": 3600,
                "ticket_tgs": encrypted_ticket.decode()
            }
            
            # Encrypt client message
            encrypted_client_message = client_cipher.encrypt(json.dumps(client_message).encode())
            
            # Send response to client
            client_socket.send(encrypted_client_message)
            print(f"Sent encrypted response to client {client_id}")
            
        except json.JSONDecodeError:
            error_msg = {"error": "Invalid request format"}
            client_socket.send(json.dumps(error_msg).encode())
        except Exception as e:
            error_msg = {"error": f"Server error: {str(e)}"}
            client_socket.send(json.dumps(error_msg).encode())
    
    def start(self):
        self.server_socket.listen(5)
        print(f"AS-TGS Server started on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection from {client_address}")
                try:
                    self.handle_client_request(client_socket, client_address)
                finally:
                    client_socket.close()
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    server = AS_TGS_Server()
    server.start()
