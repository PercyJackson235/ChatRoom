#!/usr/bin/python3
import socket, ssl
import sys
import threading
import time
import select
import signal
from Crypto.Cipher import AES
from Crypto import Random

class ChatClient(object):
    def __init__(self, address:str, port:int, name:str=None, 
                 secure:bool=False, encrypted:bool=True):
        """Chat Room client. Required are address and port. By default AES encryption used,
           but it can be turned off as `encrypted = False`. SSL is not on by default but
           can be turned on as `secure = True`."""
        self.address = address
        self.port = port
        self.name = name
        self._EOF = b'\x90' * 3 + b'\x03'
        self._STOP = b'\x90' * 3 + b'\x04'
        self._SEP = b'\x90' * 3 + b'\x02'
        self._aes_buffer = b'\x90' * 3 + b'\x05'
        self._aes_pack_len = 40
        self._running = True
        self._secure = secure
        self._encrypted = encrypted
        signal.signal(signal.SIGINT, self.stop_daemon)

    def connect(self):
        self.sock = socket.socket()
        if not ssl.os.path.exists('certs/cert.pem'):
            print("Mising certificate")
            ssl.sys.exit(1)
        if self._secure:
            context = ssl.create_default_context(cafile="certs/cert.pem")
            self.sock = context.wrap_socket(self.sock, server_hostname=self.address)
        self.sock.connect((self.address, self.port))
        if self._encrypted:
            msg = b''
            while len(msg) < self._aes_pack_len:
                msg += self.sock.recv(self._aes_pack_len)
            self._key = msg.strip(self._aes_buffer)

    def _incoming(self):
        while self._running:
            if self._running and select.select([self.sock],[],[],3.0)[0]:
                msg = self.sock.recv(2048 * 2)
                end = ''
                if self._encrypted:
                    #while (len(msg) % 16) == 4:
                    #    msg += self.sock.read(16)
                    end = msg[len(msg)-len(self._EOF):]
                    if end == self._EOF:
                        end = '\n'
                        msg = msg[:len(msg)-len(self._EOF)]
                    else:
                        end = ''
                    iv, msg = msg.split(self._SEP)
                    try:
                        msg = AES.new(self._key, AES.MODE_CBC, iv).decrypt(msg)
                    except ValueError as e:
                        print(e)
                        continue
                msg = msg.strip(b'\x00')
                if msg == self._STOP:
                    self._running = False
                else:
                    print(msg.decode() + end, end='')

    def _outgoing(self):
        while self._running:
            time.sleep(0.05)
            if select.select([sys.stdin],[],[],0.0)[0]:
                text = input()
                if text.lower() in ['exit', 'quit', 'end']:
                    self._running = False
                    break
                text = self.name.encode() + b' : ' + text.encode()# + self._EOF
                if self._encrypted:
                    text = self._padding(text)
                    iv = Random.new().read(AES.block_size)
                    text = iv + self._SEP + AES.new(self._key, AES.MODE_CBC, iv).encrypt(text)
                self.sock.sendall(text + self._EOF)
                sys.stdin.flush()
        time.sleep(2)

    def _padding(self, text:bytes):
        pad = len(text) % 16
        if pad != 0:
            text += b'\x00' * (16 - pad)
        return text

    def handle(self):
        self.connect()
        if self.name == None:
            print("What is your name?")
            self.name = input(">>> ")
        else:
            print(f"Hello, {self.name}")
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
            self.stop_daemon()
            self.sock.send(self._STOP)
            self.sock.close()
    
    def stop_daemon(self, frame=None, sig=None):
        if sig is not None:
            print()
        self._running = False
            
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Python Chatroom Client")
    parser.add_argument('-i', default="pythonchatroom.com", dest="address", help="Host")
    parser.add_argument('-p', default=3000, type=int, dest="port", help="port")
    parser.add_argument('-l', dest="name", help="Login name")
    parser.add_argument('-s', dest="secure", default=False, action="store_true", help="Turn on ssl")
    parser.add_argument('--no-encrypt', dest="encrypted", default=True, action="store_false",
                        help="Turn off AES encryption")
    args = parser.parse_args()
    client = ChatClient(**vars(args))
    client.handle()
