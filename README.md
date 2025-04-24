# Secure-Reverse-Shell-System

# Secure Reverse Shell with SSL and HMAC Authentication

## Introduction

This project develops a secure reverse shell application using SSL/TLS protocols to encrypt the communication between the client and the server, along with HMAC (Hash-based Message Authentication Code) for authenticating the client. It provides a strong authentication mechanism using passwords and RSA public/private keys.

## Key Features

- **Automatic RSA Key Generation**: RSA keys are generated to secure the communication between the client and the server.
- **SSL Certificate Creation**: OpenSSL is used to create an SSL certificate to secure the connection.
- **Authentication Protection using HMAC**: HMAC is used to verify the integrity of the communication between the client and server using a password.
- **Secure Client/Server Code**: The client connects to the server, sends commands, and executes them while the server verifies the connection before executing the commands.

## Requirements

- Python 3.x
- `pycryptodome` library (for handling RSA encryption).
- 
- opensessl must be installed on the system to generate the self-signed certificate.

## Usage

### Setting Up the Server

1. Specify the server's IP address and the port number you want to use.
2. Set the password that will be used for authentication.
3. When running the server, the program will automatically generate the necessary keys and certificate.

```bash
reverse_shell.py
Setting Up the Client
 generate the client code using the server, which the client will use to connect to the server using SSL certificate and authentication key.

run his output code into client pc > python -c "import base64; exec(base64.b64decode('<encoded client code>'))"
Executing Commands
Once the connection between the client and server is established, you can send commands via the server's command-line interface. The commands will be executed on the server, and the results will be sent back to the client.

Supported Commands
exit: Ends the connection with the server.

Any other command will be executed on the server, and the result will be sent to the client.


Notes
Ensure that the server is running properly before trying to connect to it from the client.


An SSL certificate is used to ensure secure communication between the client and the server.

Make sure OpenSSL is installed on your system to generate the certificates correctly.

