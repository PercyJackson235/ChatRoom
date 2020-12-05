#!/usr/bin/python3
import socket
import sys
import threading
import time
import select

class ChatClient(object):
    def __init__(self, address, port, name=None):
        self.address = address
        self.port = port
        self.name = name
        self._EOF = b'\x90' * 3 + b'\x03'
        self._STOP = b'\x90' * 3 + b'\x04'
        self._running = True

    def connect(self):
        self.sock = socket.socket()
        self.sock.connect((self.address, self.port))

    def _incoming(self):
        while self._running:
            if select.select([self.sock],[],[],3.0)[0] and self._running:
                msg = self.sock.recv(2048 * 2)
                print(msg.replace(self._EOF, b'\n').decode(), end='')
    def _outgoing(self):
        try:
            while self._running:
                time.sleep(0.05)
                if select.select([sys.stdin],[],[],0.0)[0]:
                    text = input()
                    if text.lower() in ['exit', 'quit', 'end']:
                        self._running = False
                        break
                    text = self.name.encode() + b' : ' + text.encode() + self._EOF
                    self.sock.sendall(text)
                    sys.stdin.flush()
            time.sleep(2)
        except:
            pass

    def handle(self):
        self.connect()
        if self.name == None:
            print("What is your name?")
            self.name = input(">>> ")
        read_thread = threading.Thread(target=self._incoming)
        write_thread = threading.Thread(target=self._outgoing)
        read_thread.start()
        write_thread.start()
        try:
            write_thread.join()
            read_thread.join()
        except:
            pass
        finally:
            self.sock.send(self._STOP)
            self.sock.close()
            
if __name__ == "__main__":
    client = ChatClient('localhost', 345)
    client.handle()