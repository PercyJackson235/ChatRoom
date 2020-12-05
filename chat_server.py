#!/usr/bin/python3
from socketserver import ThreadingTCPServer, BaseRequestHandler
import ssl, socket
from Crypto.Cipher import AES
import signal, threading, select
from time import sleep

class ChatServer(ThreadingTCPServer):
    allow_reuse_address = True
    request_queue_size = 15
    block_on_close = False
    def __init__(self, server_address, RequestHandlerClass, server_ssl=True, bind_and_activate=True):
        ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass, False)
        self.ssl = server_ssl
        self.__shutdown_request = False
        self.networked = []
        self.messagebox = []
        self.watch = threading.Thread(target=self._network_watch)
        self.watch.start()
        print(f"server_sell is",server_ssl)
        print(f"self.ssl is",self.ssl)
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
        if self.ssl:
            context = ssl.SSLContext()
            context.load_cert_chain('cert.pem','key.pem')
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()

    def verify_request(self, request, client_address):
        self.networked.append(request)
        return True

    def close_request(self, request):
        request.close()

    def _chunker(self, msg: bytes):
        for pos in range(0,len(msg), 4096):
            yield msg[pos : pos + 4096]

    def _network_watch(self):
        #print(dir(self))
        while not self.__shutdown_request:
            print(self.messagebox)
            #for msg, endpoint in self.messagebox:
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
        del self.networked
    
    def server_stop(self):
        self.__shutdown_request = True
        self.watch.join()
        print("Shutting down....")
        self.shutdown()
        self.server_close()

    def stop_thread(self, frame=None, sig=None):
        thread = threading.Thread(target=self.server_stop)
        thread.start()

class ChatHandler(BaseRequestHandler):
    def handle(self):
        EOF = b'\x90' * 3 + b'\x03'
        SHUTDOWN = b'\x90' * 3 + b'\x04'  
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
    chat = ChatServer(('localhost', 300), ChatHandler, server_ssl=False)
    chat.serve_forever()