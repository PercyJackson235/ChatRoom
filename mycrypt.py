#!/usr/bin/python3
import threading
import select
import socket, ssl
from Crypto.Cipher import AES
import sys, time

def connect(secure=None):
    sock = socket.socket()
    if secure:
        context = ssl.SSLContext()
        sock = context.wrap_socket(sock)
    sock.connect(('localhost', 300))
    for chunk in reader(sys.argv[1]):
        sock.sendall(chunk)
    sock.close()

def encrypted_connect(secure=None):
    sock = socket.socket()
    if secure:
        context = ssl.SSLContext()
        context.load_verify_locations('cert.pem')
        sock = context.wrap_socket(sock)
        print(sock.version())
    sock.connect(('localhost', 300))
    key = 'PercyJackson2345'
    cipherobj = AES.new(key)
    for chunk in reader(sys.argv[1]):
        ctext = cipherobj.encrypt(chunk)
        sock.sendall(ctext)
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

def reader(filename):
    with open(filename, 'rb') as f:
        while True:
            text = f.read(1008)
            print(len(text))
            if len(text) == 0:
                break
            pad = len(text) % 16
            if pad != 0:
                text += b'\x00' * (16 - pad)
            yield text

if len(sys.argv) > 2:
    encrypted_connect(True)
else:
    encrypted_connect()
#connect(True)
