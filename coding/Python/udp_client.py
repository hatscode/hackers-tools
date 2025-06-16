#!/bin/python3

import socket

target_host = '127.0.0.1'
target_port = 80

# create the client object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send some data
client.sendto(b"AAABBBCCC", (target_host, target_port))

data, addr = client.recvfrom(4096)

print(data)

