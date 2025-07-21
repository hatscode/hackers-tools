#!/bin/python3

import socket

target_host = 'google.com'
target_port = 80

#create the socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client to the target host and port
client.connect((target_host, target_port))

# send some data
client.send("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".encode())

responce = client.recv(4096)

print(responce)