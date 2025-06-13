#!/bin/python3

import socket

target_host = 'google.com'
target_port = 80

# create the socket client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect
client.connect((target_host, target_port))

# send some data
client.send("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".encode())

response = client.recv(4000)

print(response) # print the response