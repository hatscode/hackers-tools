#!/bin/python3

# A simple TCP client that connects to a server, sends a message, and receives a response.
import socket   

def tcp_client():
    """Create a TCP client that connects to a server, sends a message, and receives a response."""
    
    # Define the server address and port
    server_address = ('localhost', 65432)
    
    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to the server
        sock.connect(server_address)
        
        # Send data
        message = 'Hello, Server!'
        sock.sendall(message.encode())
        
        # Receive response
        response = sock.recv(1024)
        print(f'Received: {response.decode()}')