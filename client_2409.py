#!/usr/bin/env python3
import socket
import sys
import os

PORT = 50409
HOST = 'localhost'
TOKEN_FILE = 'token.txt'

def send_message(sock, payload):
    message = f"LEN:{len(payload)}\n{payload}"
    sock.send(message.encode())
    return sock.recv(4096).decode()

def save_token(token):
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            return f.read().strip()
    return None

def delete_token():
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)

def main():
    # Connect ONCE at the beginning
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    
    print("Connected to server at {}:{}".format(HOST, PORT))
    print("="*50)
    print("Commands: REGISTER, LOGIN, LOGOUT, GET_DATA")
    print("Type 'LOGOUT' to disconnect from server and exit")
    
    
    # Load existing token from file
    token = load_token()
    if token:
        print(f"[INFO] Loaded existing token: {token[:20]}...")
    
    while True:
        try:
            user_input = input("\n> ").strip()
            
            if not user_input:
                continue
            
            parts = user_input.split()
            cmd = parts[0].upper() if parts else ""
            
            # REGISTER command
            if cmd == "REGISTER" and len(parts) >= 3:
                username = parts[1]
                password = parts[2]
                response = send_message(sock, f"REGISTER {username} {password}")
                print(response)
            
            # LOGIN command
            elif cmd == "LOGIN" and len(parts) >= 3:
                username = parts[1]
                password = parts[2]
                response = send_message(sock, f"LOGIN {username} {password}")
                print(response)
                
                # Extract and save token from response
                if "TOKEN:" in response:
                    token = response.split("TOKEN:")[1].strip().split()[0]
                    save_token(token)
                    print(f"[INFO] Token saved automatically")
            
            # LOGOUT command - sends logout to server, then closes connection and exits
            elif cmd == "LOGOUT":
                if token:
                    response = send_message(sock, f"LOGOUT TOKEN:{token}")
                    print(response)
                    delete_token()
                    print("[INFO] Logged out successfully")
                else:
                    response = send_message(sock, "LOGOUT")
                    print(response)
                print("Closing connection...")
                break
            
            # Any other command (GET_DATA, etc.)
            else:
                if token:
                    response = send_message(sock, f"{user_input} TOKEN:{token}")
                else:
                    response = send_message(sock, user_input)
                print(response)
                
        except KeyboardInterrupt:
            print("\n[INFO] Interrupted by user")
            break
        except ConnectionResetError:
            print("Server disconnected. Exiting...")
            break
        except Exception as e:
            print(f"Error: {e}")
            break
    
    # Close connection at the end
    sock.close()
    print("Connection closed. Goodbye!")

if __name__ == "__main__":
    main()
