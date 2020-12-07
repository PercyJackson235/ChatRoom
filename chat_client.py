#!/usr/bin/python3
import socket, ssl
import sys, os
import threading
import time
import select
import signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

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
        if bool(self._secure):
            if not os.path.exists(self._secure):
                print("Mising certificate")
                sys.exit(1)
            context = ssl.create_default_context(cafile=self._secure)
            self.sock = context.wrap_socket(self.sock, server_hostname=self.address)
        try:
            self.sock.connect((self.address, self.port))
        except ConnectionRefusedError:
            self._running = False
            self._refused = True
            return
        if self._encrypted:
            msg = b''
            while len(msg) < self._aes_pack_len:
                msg += self.sock.recv(self._aes_pack_len)
            self._key = msg.strip(self._aes_buffer)
        self._running = True

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
                        msg = self._aes_decypt(msg, iv)
                    except ValueError as e:
                        print(e)
                        continue
                msg = msg.strip(b'\x00')
                if msg == self._STOP:
                    self._running = False
                    self.sock.sendall(self._STOP)
                    self.sock.close()
                    cmd = ''
                    answer_dict = {'y' : True , 'n' : False, 'yes': True, 'no' : False}
                    while True:
                        cmd = input("We have lost contact with the server.\n"
                                    "Would you like to attempt reconnection? [yes | no] ").strip()
                        time.sleep(1)
                        if cmd.lower() not in answer_dict.keys():
                            continue
                        if answer_dict[cmd]:
                            print("Ok! Attempting to reconnect to server.")
                            if self._reconnect_check():
                                print("We have reconnected to server.")
                                break
                        else:
                            print("Ok. Shutting Down.")
                            break
                else:
                    print(msg.decode() + end, end='')

    def _aes_decypt(self, msg:bytes, iv:bytes):
        decryptor = Cipher(algorithms.AES(self._key), modes.CBC(iv)).decryptor()
        return decryptor.update(msg) + decryptor.finalize()

    def _aes_encrypt(self, msg:bytes):
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(self._key), modes.CBC(iv))
        encryptor = encryptor.encryptor()
        ciphertext = encryptor.update(msg) + encryptor.finalize()
        return iv + self._SEP + ciphertext

    def _outgoing(self):
        while self._running:
            time.sleep(0.05)
            if select.select([sys.stdin],[],[],0.0)[0]:
                text = input()
                if text.lower() in ['exit', 'quit', 'end']:
                    self._running = False
                    break
                text = self.name.encode() + b' : ' + text.encode()
                if self._encrypted:
                    text = self._padding(text)
                    text = self._aes_encrypt(text)
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
            if hasattr(self,'_refused') and not self._refused:
                self.sock.send(self._STOP)
            self.sock.close()
    
    def stop_daemon(self, frame=None, sig=None):
        if sig is not None:
            print()
        self._running = False

    def _reconnect_check(self):
        count = 0
        for i in sleep_time():
            count += i
            time.sleep(i)
            self.connect()
            time.sleep(1)
            if self._running:
                return True
            if count > 60: #540:
                return False

def sleep_time():
    secs = 5
    while True:
        yield secs
        if secs < 30:
            secs += 5
        elif secs == 30:
            secs = 5

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Python Chatroom Client", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', default="pythonchatroom.com", dest="address", help="Host")
    parser.add_argument('-p', default=3000, type=int, dest="port", help="port")
    parser.add_argument('-l', dest="name", help="Login name")
    parser.add_argument('-s', dest="secure", default=False, const="certs/cert.pem", nargs="?",
                        help=f"Turn on ssl. -s defaults to {os.path.sep.join(('certs','cert.pem'))}"
                        "\nAdd a filename after the switch option to\nspecify an alternate certificate.")
    parser.add_argument('--no-encrypt', dest="encrypted", default=True, action="store_false",
                        help="Turn off AES encryption")
    args = parser.parse_args()
    client = ChatClient(**vars(args))
    client.handle()
