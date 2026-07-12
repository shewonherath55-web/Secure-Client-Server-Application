# Secure-Client-Server-Application
IE2102 Module | Network Programming project featuring a secure TCP client-server application built with C and Python.

# Project Overview

This project is a secure client-server application developed as part of the Network Programming module. It implements a custom TCP communication protocol using a C-based server and a Python client. The server supports concurrent client connections through multiprocessing, secure user authentication with salted password hashing, session token management, abuse protection mechanisms, and persistent audit logging.

# Technology Used
| Technology  | Purpose                 |
| ----------- | ----------------------- |
| C           | TCP Server              |
| Python      | Client Application      |
| TCP Sockets | Network Communication   |
| GCC         | Compilation             |
| Make        | Build Automation        |
| Linux       | Development Environment |

# Project Structure
.
├── server_xxxx.c
├── client_xxxx.py
├── Makefile_xxxx
├── server_xxxxxxxx.log
├── README.md

# Build & Run
Compile the server using the provided Makefile.
-> make -f Makefile_2409

Or compile manually.
gcc server_2409.c -o server

Start the Server
-> ./server

Run the Python Client
-> python3 client_2409.py

# Example Commands
REGISTER alice password123

LOGIN alice password123

LOGOUT
