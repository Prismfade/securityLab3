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
        self.port = 9009
        
        # Pre-shared DES keys (must be exactly 8 bytes for DES)
        self.Kc = b'KC_KEY12'   # key shared between Client and AS (8 bytes)
        self.Ktgs = b'KT_KEY12' # key shared between AS and TGS (8 bytes)

        self.IDc = "CIS3319USERID"
        self.IDtgs = "CIS3319TGSID"
        self.IDv = "CIS3319SERVERID"
        
        unix_epoch_time = int(time.time())
        print(f"Current Unix Epoch Time: {unix_epoch_time}")

        # Initialize server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))

    # ---------- AS side: create Tickettgs ----------
    def TGS_generate_Ticket(self, IDc, IDtgs, client_addr):
        # Generate session key Kc_tgs (16 bytes as required)
        Kc_tgs = os.urandom(16)  # 16 bytes session key

        # Encrypt the session key inside the ticket as well
        enc_Kc_tgs = self.DES_encrypt(self.Ktgs, Kc_tgs)

        # Build ticket fields: Ktgs, kctgs, IDc, ADc, IDtgs, TS2, Lifetime2
        ticket_data = {
            "Ktgs": self.Ktgs.hex(),
            "kctgs": enc_Kc_tgs.hex(),
            "IDc": IDc,
            "ADc": client_addr,
            "IDtgs": IDtgs,
            "TS2": int(time.time()),
            "Lifetime2": 86400  # 24 hours
        }
        ticket_json = json.dumps(ticket_data).encode()
        encrypted_ticket = self.DES_encrypt(self.Ktgs, ticket_json)
        return encrypted_ticket, Kc_tgs

    def handle_client_ASC(self, client_socket, request):
        """Request from client to AS (for Tickettgs)."""
        try:
            IDc = request.get('IDc')
            IDtgs = request.get('IDtgs')

            # get client address for ADc
            try:
                ip, port = client_socket.getpeername()
                client_addr = f"{{'{ip}':{port}}}"
            except Exception:
                client_addr = "{'unknown':0}"

            encrypted_ticket, Kc_tgs = self.TGS_generate_Ticket(IDc, IDtgs, client_addr)

            response = {
                'ticket': encrypted_ticket.hex()
            }
            response_json = json.dumps(response).encode()

            # encrypt response with client's key Kc
            encrypted_response = self.DES_encrypt(self.Kc, response_json)
            client_socket.send(encrypted_response)
            print(f"[AS] Sent Tickettgs to client {client_addr}")

        except Exception as e:
            import traceback
            print(f"Error handling AS client: {e}")
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    # ---------- TGS side: create Ticketv ----------
    def generate_Ticketv(self, IDc, IDv, client_addr, Kc_tgs_unused):
        # Generate session key Kc_v (16 bytes as required)
        Kc_v = os.urandom(16)  # 16 bytes session key

        # Encrypt the session key inside the ticket as well
        enc_Kc_v = self.DES_encrypt(self.Ktgs, Kc_v)

        # Build ticket fields: Kv, kcv, IDc, ADc, IDv, TS4, Lifetime4
        ticket_data = {
            "Kv": self.Ktgs.hex(),
            "kcv": enc_Kc_v.hex(),
            "IDc": IDc,
            "ADc": client_addr,
            "IDv": IDv,
            "TS4": int(time.time()),
            "Lifetime4": 86400  # 24 hours
        }
        ticket_json = json.dumps(ticket_data).encode()
        encrypted_ticket = self.DES_encrypt(self.Ktgs, ticket_json)
        return encrypted_ticket, Kc_v

    def handle_client_TGSClient(self, client_socket, request):
        """Request from client to TGS (for Ticketv)."""
        try:
            print("Raw TGS request parsed:", request)

            IDv = request.get('IDv')
            Tickettgs_hex = request.get('Tickettgs')
            authenticator = request.get('authenticator')  # you can verify later

            if Tickettgs_hex is None or IDv is None:
                print("Missing IDv or Tickettgs in TGS request")
                return

            # Decrypt Tickettgs
            ticket_bytes = bytes.fromhex(Tickettgs_hex)
            ticket_plain = self.DES_decrypt(self.Ktgs, ticket_bytes)
            print("Decrypted Tickettgs JSON:", ticket_plain.decode())

            ticket = json.loads(ticket_plain.decode())

            IDc = ticket.get('IDc')
            ADc = ticket.get('ADc')

            print(f"[TGS] Extracted from Tickettgs: IDc={IDc}, ADc={ADc}")

            encrypted_ticketv, Kc_v = self.generate_Ticketv(IDc, IDv, ADc, None)

            response = {
                "Kcv": Kc_v.hex(),          # session key for client–server
                "IDv": IDv,
                "TS4": int(time.time()),
                "Ticketv": encrypted_ticketv.hex()
            }
            response_json = json.dumps(response).encode()
            client_socket.send(response_json)
            print("[TGS] Sent Ticketv to client")

        except Exception as e:
            import traceback
            print(f"Error handling TGS client: {e}")
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    # ---------- DES helpers ----------
    def DES_encrypt(self, key: bytes, data: bytes) -> bytes:
        des = DES.new(key, DES.MODE_ECB)
        pad_len = 8 - (len(data) % 8)
        if pad_len == 0:
            pad_len = 8
        data += bytes([pad_len]) * pad_len
        encrypted_data = des.encrypt(data)
        return encrypted_data

    def DES_decrypt(self, key: bytes, data: bytes) -> bytes:
        des = DES.new(key, DES.MODE_ECB)
        plaintext = des.decrypt(data)
        pad_len = plaintext[-1]
        if pad_len < 1 or pad_len > 8:
            return plaintext
        return plaintext[:-pad_len]

    # ---------- Main loop ----------
    def start(self):
        self.server_socket.listen(5)
        print(f"AS/TGS Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection from {addr} has been established.")

            try:
                data = client_socket.recv(4096)
                if not data:
                    client_socket.close()
                    continue

                print("Raw request bytes:", data)

                try:
                    request = json.loads(data.decode())
                    print("Parsed request:", request)
                except Exception:
                    print("Received non-JSON request from client:", data)
                    client_socket.close()
                    continue

                # Decide whether this is AS or TGS based on fields
                if "IDc" in request and "IDtgs" in request and "TS1" in request:
                    # AS phase
                    self.handle_client_ASC(client_socket, request)

                elif "IDv" in request and "Tickettgs" in request:
                    # TGS phase
                    self.handle_client_TGSClient(client_socket, request)

                else:
                    print("Unknown request type:", request)
                    client_socket.close()

            except Exception as e:
                import traceback
                print("Error in main loop:", e)
                traceback.print_exc()
                try:
                    client_socket.close()
                except:
                    pass


if __name__ == "__main__":
    server = AS_TGS_Server()
    server.start()
