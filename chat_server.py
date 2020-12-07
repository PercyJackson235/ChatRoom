#!/usr/bin/python3
from socketserver import ThreadingTCPServer, BaseRequestHandler
import ssl, socket
from Crypto.Cipher import AES
from Crypto import Random
import signal, threading, select
from time import sleep
import os, subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

class ChatServer(ThreadingTCPServer):
    allow_reuse_address = True
    request_queue_size = 15
    block_on_close = False
    def __init__(self, server_address, RequestHandlerClass, server_ssl=True, bind_and_activate=True, encrypted=True):
        ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass, False)
        self.secure = server_ssl
        self.__shutdown_request = False
        self.networked = []
        self.messagebox = []
        self.watch = threading.Thread(target=self._network_watch)
        self.watch.start()
        #self._key = Random.new().read(AES.key_size[-1])
        self._key = os.urandom(32)
        #self._cipherobj = AES.new(self._key, AES.MODE_CBC, Random.new().read(AES.block_size))
        self._encrypted = encrypted
        self._aes_buffer = b'\x90' * 3 + b'\x05'
        self._SEP = b'\x90' * 3 + b'\x02'
        self._EOF = b'\x90' * 3 + b'\x03'
        self._SHUTDOWN = b'\x90' * 3 + b'\x04'
        signal.signal(signal.SIGINT, self.stop_thread)
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except:
                self.server_close()
                raise

    def server_bind(self):
        if self.allow_reuse_address:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        self.socket.listen()
        self.server_address = self.socket.getsockname()
        if self.secure:
            cert, key = 'certs/cert.pem', 'certs/key.pem'
            if not all(map(os.path.exists, (cert, key))):
                print("Missing certificates. Running cert_create.sh")
                output = open(os.devnull, 'w+')
                if 0 != subprocess.run('/bin/sh cert_create.sh'.split(),stdout=output, stderr=output).returncode:
                    print("Unrecoveable error. Missing Certificate and cert_create.sh failed!")
                    os.sys.exit(1)
            context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert, keyfile=key)
            self.socket = context.wrap_socket(self.socket, server_side=True)
        print(f"Server listening on {self.socket.getsockname()}.")

    def verify_request(self, request, client_address):
        if self._encrypted:
            request.sendall(self._aes_buffer + self._key + self._aes_buffer)
        self.networked.append(request)
        return True

    def close_request(self, request):
        request.close()

    def _chunker(self, msg: bytes):
        for pos in range(0,len(msg), 4096):
            yield msg[pos : pos + 4096]

    def _network_watch(self):
        while not self.__shutdown_request:
            while 0 < len(self.messagebox):
                msg, endpoint = self.messagebox.pop(0)
                closed_connections = []
                for client in self.networked:
                    if client.fileno() == -1:
                        closed_connections.append(client)
                    elif client.getpeername() == endpoint:
                        pass
                    else:
                        for chunk in self._chunker(msg):
                            client.sendall(chunk)
                for sock in closed_connections:
                    self.networked.remove(sock)
            sleep(3)
    
    def server_stop(self):
        SHUTDOWN = self._SHUTDOWN
        if self._encrypted:
            SHUTDOWN = self._padding(SHUTDOWN)
            #SHUTDOWN = self._cipherobj.IV + SEP + self._cipherobj.encrypt(SHUTDOWN)
            SHUTDOWN = self._aes_encrypt(SHUTDOWN)
        self.__shutdown_request = True
        self.watch.join()
        print("\nShutting down....")
        for sock in self.networked:
            if sock.fileno() != -1:
                sock.sendall(SHUTDOWN)
        self.shutdown()
        #print("Hitting server_close()")
        self.server_close()
        os.sys.exit(0)

    def _padding(self, text:bytes):
        pad = len(text) % 16
        if pad != 0:
            text += b'\x00' * (16 - pad)
        return text

    def stop_thread(self, frame=None, sig=None):
        thread = threading.Thread(target=self.server_stop)
        thread.start()

    def _aes_encrypt(self, msg:bytes):
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(self._key), modes.CBC(iv))
        encryptor = encryptor.encryptor()
        ciphertext = encryptor.update(msg) + encryptor.finalize()
        return iv + self._SEP + ciphertext

class ChatHandler(BaseRequestHandler):
    def handle(self):
        EOF = self.server._EOF
        SHUTDOWN = self.server._SHUTDOWN  
        while self.request.fileno() != -1:
            sent_data = b''
            while True:
                sleep(0.05)
                if select.select([self.request],[],[], 0.0):
                    data = self.request.recv(2048)
                    sent_data += data
                    if EOF in sent_data:
                        break
                    if data == b'':
                        break
                    if sent_data == SHUTDOWN:
                        break
            if sent_data == SHUTDOWN:
                self.request.close()
            elif sent_data != b'':
                self.server.messagebox.append((sent_data, self.request.getpeername()))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A Chat Server written in Python3.")
    parser.add_argument('-i', default="pythonchatroom.com", dest="host", help="Host")
    parser.add_argument('-p', default=3000, type=int, dest="port", help="port")
    parser.add_argument('-s', dest="server_ssl", default=False, action="store_true", help="Turn on ssl")
    parser.add_argument('--no-encrypt', dest="encrypted", default=True, action="store_false",
                        help="Turn off AES encryption")
    args = parser.parse_args()
    args.server_address = args.host, args.port
    args.RequestHandlerClass = ChatHandler
    del args.host, args.port
    chat = ChatServer(**vars(args))
    chat.serve_forever()