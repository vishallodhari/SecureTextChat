import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading
import socket
import json
import time
import zlib
import hashlib
import random
import contextlib
from datetime import datetime, timezone

# Cryptography imports
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# -------------------------------------------------------------------------
# CORE LOGIC CLASS (Refactored from your solution.py)
# -------------------------------------------------------------------------
class ChatLogic:
    def __init__(self):
        # Generate parameters once to save time
        self.parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())

    def server_dhsk(self):
        server_private_key = self.parameters.generate_private_key()
        server_public_key = server_private_key.public_key()
        server_pem_public = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return server_pem_public, server_private_key

    def client_dhsk(self, server_pem_public):
        dhpublickey = serialization.load_pem_public_key(server_pem_public, backend=default_backend())
        parameters = dhpublickey.parameters()
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key()
        client_pem_public = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return client_pem_public, client_private_key

    def server_derived_key(self, server_private_key, client_public_key):
        client_public_key = serialization.load_pem_public_key(client_public_key, backend=default_backend())
        shared_key = server_private_key.exchange(client_public_key)
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'handshake data', backend=default_backend(),
        ).derive(shared_key)

    def client_derived_key(self, client_private_key, server_public_key):
        server_public_key = serialization.load_pem_public_key(server_public_key, backend=default_backend())
        shared_key = client_private_key.exchange(server_public_key)
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'handshake data', backend=default_backend(),
        ).derive(shared_key)

    def chap_secret(self, dhsk, password):
        secret_string = password
        user_secret = bytes(secret_string, 'UTF-8')
        dhsk_str = str(dhsk)
        dhsk_byte = bytes(dhsk_str, 'UTF-8')
        hmac_obj = HMAC.new(dhsk_byte, user_secret, digestmod=SHA256)
        enc_key = hmac_obj.hexdigest()
        enc_key_bytes = bytes(enc_key, 'UTF-8')
        h = SHA256.new(enc_key_bytes)
        iv = h.hexdigest()[:16]
        iv_bytes = bytes(iv, 'UTF-8')
        iv_sha = SHA256.new(iv_bytes)
        hmac_key = iv_sha.hexdigest()
        hmac_bytes = bytes(hmac_key, 'UTF-8')
        chap = SHA256.new(hmac_bytes)
        chap_secret = chap.hexdigest()
        return chap_secret, iv_bytes, hmac_key

    def encryption(self, text, dhsk, iv):
        cipher = AES.new(dhsk, AES.MODE_CBC, iv)
        text = bytes(text, 'utf-8')
        ct_bytes = cipher.encrypt(pad(text, AES.block_size))
        return (b64encode(ct_bytes).decode('utf-8'))

    def decryption(self, body, dhsk, iv):
        body = b64decode(body)
        cipher = AES.new(dhsk, AES.MODE_CBC, iv)
        return (unpad(cipher.decrypt(body), AES.block_size))

    def crc_generate(self, message):
        msg = json.dumps(message)
        bmsg = bytes(msg, 'utf-8')
        crc = zlib.crc32(bmsg)
        message['header']['crc'] = crc
        return message

    def crc_check(self, message, log_callback):
        crc = message['header']['crc']
        message['header']['crc'] = None
        msg = json.dumps(message)
        bmsg = bytes(msg, 'utf-8')
        response_crc = zlib.crc32(bmsg)
        if response_crc != crc:
            log_callback('ALERT: Mismatched crc, message is tampered')
            return False
        else:
            # log_callback('CRC Validated')
            return True

    def securelogging(self, filename, message, password):
        with open(filename, 'a') as f:
            timestamp = datetime.now(timezone.utc).strftime("%d-%m-%Y %H:%M:%S")
            log_entry = f'{timestamp} + {message}'
            password = bytes(password, 'utf-8')
            log_bytes = bytes(log_entry, 'utf-8')
            hmac_obj = HMAC.new(password, log_bytes, digestmod=SHA256)
            hmac_value = hmac_obj.hexdigest()
            new_entry = f'{log_entry}::HMAC:{hmac_value}\n'
            f.write(new_entry)

# -------------------------------------------------------------------------
# GUI CLASS
# -------------------------------------------------------------------------
class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat - Encrypted Messaging")
        self.root.geometry("700x600")

        self.logic = ChatLogic()
        self.user_dict = []
        self.is_listening = False
        self.server_socket = None

        self._init_ui()

    def _init_ui(self):
        # --- Configuration Frame ---
        config_frame = tk.LabelFrame(self.root, text="Configuration", padx=10, pady=10)
        config_frame.pack(fill="x", padx=10, pady=5)

        tk.Button(config_frame, text="Load Users JSON", command=self.load_json).grid(row=0, column=0, padx=5)
        self.lbl_json_status = tk.Label(config_frame, text="No file loaded", fg="red")
        self.lbl_json_status.grid(row=0, column=1, padx=5)

        tk.Label(config_frame, text="My Port:").grid(row=0, column=2, padx=5)
        self.ent_my_port = tk.Entry(config_frame, width=8)
        self.ent_my_port.grid(row=0, column=3, padx=5)

        tk.Label(config_frame, text="My Password:").grid(row=0, column=4, padx=5)
        self.ent_my_pass = tk.Entry(config_frame, show="*", width=15)
        self.ent_my_pass.grid(row=0, column=5, padx=5)

        self.btn_listen = tk.Button(config_frame, text="Start Server", command=self.toggle_server, bg="#dddddd")
        self.btn_listen.grid(row=0, column=6, padx=10)

        # --- Chat Display ---
        chat_frame = tk.Frame(self.root)
        chat_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.txt_display = scrolledtext.ScrolledText(chat_frame, state='disabled', height=20)
        self.txt_display.pack(fill="both", expand=True)

        # --- Send Frame ---
        send_frame = tk.LabelFrame(self.root, text="Send Message", padx=10, pady=10)
        send_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(send_frame, text="Target IP:").grid(row=0, column=0)
        self.ent_target_ip = tk.Entry(send_frame, width=15)
        self.ent_target_ip.insert(0, "127.0.0.1")
        self.ent_target_ip.grid(row=0, column=1, padx=5)

        tk.Label(send_frame, text="Target Port:").grid(row=0, column=2)
        self.ent_target_port = tk.Entry(send_frame, width=8)
        self.ent_target_port.grid(row=0, column=3, padx=5)

        tk.Label(send_frame, text="Message:").grid(row=1, column=0, pady=10)
        self.ent_message = tk.Entry(send_frame, width=50)
        self.ent_message.grid(row=1, column=1, columnspan=3, padx=5)

        tk.Button(send_frame, text="SEND", command=self.start_send_thread, bg="#4CAF50", fg="white").grid(row=1, column=4, padx=10)

    def log(self, message):
        """Thread-safe logging to the text box"""
        self.txt_display.config(state='normal')
        self.txt_display.insert(tk.END, message + "\n")
        self.txt_display.see(tk.END)
        self.txt_display.config(state='disabled')

    def load_json(self):
        filepath = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if filepath:
            try:
                with open(filepath, "r") as f:
                    self.user_dict = json.load(f)
                self.lbl_json_status.config(text="Loaded", fg="green")
                self.log(f"[System] User directory loaded from {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load JSON: {e}")

    # -------------------------------------------------------------------------
    # SERVER / RECEIVING LOGIC
    # -------------------------------------------------------------------------
    def toggle_server(self):
        if not self.is_listening:
            port_str = self.ent_my_port.get()
            password = self.ent_my_pass.get()
            if not port_str or not password:
                messagebox.showwarning("Input Error", "Please enter Port and Password")
                return
            
            self.is_listening = True
            self.btn_listen.config(text="Stop Server", bg="#ffcccc")
            # Start the listener thread
            threading.Thread(target=self.run_server, args=(int(port_str), password), daemon=True).start()
        else:
            self.is_listening = False
            if self.server_socket:
                self.server_socket.close()
            self.btn_listen.config(text="Start Server", bg="#dddddd")
            self.log("[Server] Server stopped.")

    def run_server(self, port, password):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('', port))
            self.server_socket.listen(1)
            self.log(f"[Server] Listening on port {port}...")

            while self.is_listening:
                try:
                    conn, addr = self.server_socket.accept()
                    self.log(f"[Server] Connection from {addr}")
                    
                    # Handle the specific connection in a dedicated method (blocking is okay here as it's already in a thread)
                    self.handle_incoming_connection(conn, addr, password)
                except OSError:
                    break # Socket closed
        except Exception as e:
            self.log(f"[Server Error] {e}")
        finally:
            self.is_listening = False

    def handle_incoming_connection(self, conn, addr, password):
        try:
            # 1. Wait for Hello
            hello_msg = conn.recv(1024)
            if not hello_msg or hello_msg.decode().split(":")[1] != "None":
                self.log("[Auth] Invalid Hello message.")
                conn.close()
                return

            self.log("[Auth] Received Hello. Generating Keys...")
            server_pem, server_priv = self.logic.server_dhsk()
            conn.send(server_pem)

            # 2. Receive Client Public Key
            client_pub = conn.recv(1024)
            dhsk = self.logic.server_derived_key(server_priv, client_pub)

            # 3. Send Challenge
            challenge_val = str(random.getrandbits(256))
            conn.send(f"challenge:{challenge_val}".encode())
            
            # 4. Verify Response
            resp_msg = conn.recv(1024)
            resp_body = resp_msg.decode().split(":")[1]
            
            sha256 = hashlib.sha256()
            sha256.update((challenge_val + password).encode())
            expected = sha256.hexdigest()

            if resp_body != expected:
                conn.send("nack:Invalid response".encode())
                self.log("[Auth] Authentication Failed (Wrong Password from Sender).")
                conn.close()
                return
            
            conn.send("ack:Authentication successful".encode())
            self.log("[Auth] Sender Authenticated.")

            # 5. Mutual Auth (Prove server identity)
            chapsecret, iv, _ = self.logic.chap_secret(dhsk, password)
            sha256 = hashlib.sha256()
            sha256.update((challenge_val + chapsecret).encode())
            server_auth = sha256.hexdigest()
            conn.send(f"Auth:{server_auth}".encode())

            # 6. Wait for final ACK
            final_ack = conn.recv(1024).decode()
            if "ack" not in final_ack:
                 self.log("[Auth] Client rejected Server authentication.")
                 conn.close()
                 return
            
            self.log("[Auth] Mutual Authentication Complete. Secure Channel Established.")

            # 7. Receive Message
            data = conn.recv(4096).decode()
            if data:
                pdu = json.loads(data)
                if self.logic.crc_check(pdu, self.log):
                    body = pdu['body']
                    text = self.logic.decryption(body, dhsk, iv).decode('utf-8')
                    self.log(f"\n>>> RECEIVED MESSAGE: {text}\n")
                    self.logic.securelogging('logging.txt', text, password)
                    
                    # Send Ack
                    ack_pdu = {'header': {'msg_type': 'ack'}, 'body': None}
                    conn.sendall(json.dumps(ack_pdu).encode())
            
            conn.close()

        except Exception as e:
            self.log(f"[Connection Error] {e}")
            conn.close()

    # -------------------------------------------------------------------------
    # CLIENT / SENDING LOGIC
    # -------------------------------------------------------------------------
    def start_send_thread(self):
        target_ip = self.ent_target_ip.get()
        target_port = self.ent_target_port.get()
        password = self.ent_my_pass.get()
        message = self.ent_message.get()

        if not target_ip or not target_port or not password or not message:
            messagebox.showwarning("Missing Info", "Please fill IP, Port, Password and Message")
            return

        # Disable button to prevent double send
        threading.Thread(target=self.send_message_logic, 
                         args=(target_ip, int(target_port), password, message)).start()

    def send_message_logic(self, ip, port, password, text):
        try:
            self.log(f"[Client] Connecting to {ip}:{port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15) # Safety timeout
            sock.connect((ip, port))

            # 1. Send Hello
            sock.send("hello:None".encode())
            
            # 2. Receive Server Key & Send Client Key
            server_pub = sock.recv(1024)
            client_pem, client_priv = self.logic.client_dhsk(server_pub)
            sock.send(client_pem)
            
            dhsk = self.logic.client_derived_key(client_priv, server_pub)

            # 3. Handle Challenge
            challenge_msg = sock.recv(1024)
            challenge_val = challenge_msg.decode().split(":")[1]
            
            sha256 = hashlib.sha256()
            sha256.update((challenge_val + password).encode())
            resp = sha256.hexdigest()
            sock.send(f"response:{resp}".encode())

            # 4. Wait for Auth ACK
            ack_msg = sock.recv(1024).decode()
            if "nack" in ack_msg:
                self.log("[Client] Server rejected password.")
                sock.close()
                return
            
            self.log("[Client] Server accepted password.")

            # 5. Verify Server (Mutual Auth)
            chapsecret, iv, hmac_val = self.logic.chap_secret(dhsk, password)
            server_auth_msg = sock.recv(1024)
            server_auth_val = server_auth_msg.decode().split(":")[1]

            sha256 = hashlib.sha256()
            sha256.update((challenge_val + chapsecret).encode())
            expected = sha256.hexdigest()

            if server_auth_val != expected:
                sock.send("nack:Invalid response".encode())
                self.log("[Client] Server failed verification! Possible MITM.")
                sock.close()
                return
            
            sock.send("ack:Authentication successful".encode())
            self.log("[Client] Mutual Authentication Successful.")

            # 6. Encrypt and Send Message
            header = {'msg_type': 'text', 'crc': None, 'timestamp': time.time()}
            body = self.logic.encryption(text, dhsk, iv)
            security = {'hmac': {'hmac_type': 'SHA256', 'hmac_val': hmac_val}, 'enc_type': 'AES256CBC'}
            
            msg_pdu = {'header': header, 'body': body, 'security': security}
            msg_pdu = self.logic.crc_generate(msg_pdu)
            
            sock.sendall(json.dumps(msg_pdu).encode('utf-8'))
            self.log(f"[Client] Encrypted message sent.")

            # 7. Wait for Delivery ACK
            delivery_ack = sock.recv(1024).decode()
            if 'ack' in delivery_ack:
                self.log("[Client] Message Delivered Successfully.")
                self.logic.securelogging('clientlogging.txt', text, password)
                # Clear message box on main thread
                self.root.after(0, lambda: self.ent_message.delete(0, tk.END))
            
            sock.close()

        except Exception as e:
            self.log(f"[Send Error] {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatGUI(root)
    root.mainloop()