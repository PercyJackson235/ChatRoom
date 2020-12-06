#!/usr/bin/python3
import tkinter
from tkinter import scrolledtext
from tkinter import simpledialog
import time
import socket
from threading import Thread
import select
from Crypto.Cipher import AES
from Crypto import Random
import ssl

class ChatWindow(object):
    def __init__(self, address:str = None, port:int = 3000, name:str = None, secure=False, encrypted=True):
        self.address = address
        self.port = int(port)
        self.name = name
        self._EOF = b'\x90' * 3 + b'\x03'
        self._STOP = b'\x90' * 3 + b'\x04'
        self._SEP = b'\x90' * 3 + b'\x02'
        self._aes_buffer = b'\x90' * 3 + b'\x05'
        self._aes_pack_len = 40
        self._encrypted = encrypted
        self._running = False
        self._exit = False
        self.window = tkinter.Tk()
        self.window.attributes('-zoomed', True)
        if self.name:
            self.window.title(f'PyChat[{self.name}]')
        else:
            self.window.title('PyChat')
        topframe = tkinter.Frame(self.window)
        self.startbtn = tkinter.Button(topframe, text='Connect', command=self.connect)
        self.stopbtn = tkinter.Button(topframe, text='Disconnect', command=self.disconnect)
        self.stopbtn.configure(state='disabled')
        self.stopbtn.pack(side=tkinter.LEFT)
        self.startbtn.pack(side=tkinter.RIGHT)
        topframe.pack(side=tkinter.TOP)#, pady=(5,0))
        middleframe = tkinter.Frame(self.window)
        self.messages = scrolledtext.ScrolledText(middleframe)
        #self.messages.insert(tkinter.END, 'hello')
        self.messages.pack(expand=True, fill=tkinter.BOTH, side=tkinter.BOTTOM, pady=(5,2), padx=10)
        self.messages.configure(state="disabled")
        middleframe.pack(expand=True, fill=tkinter.BOTH)
        bottomframe = tkinter.Frame(self.window)
        self.textbox = tkinter.Text(bottomframe)
        self.textbox.pack(expand=True, fill=tkinter.BOTH, side=tkinter.LEFT, pady=(0,5), padx=10)
        self.sendbtn = tkinter.Button(bottomframe, text='Send', command=self.send)
        self.sendbtn.pack(side=tkinter.RIGHT)
        bottomframe.pack(expand=True, fill=tkinter.BOTH)
        self.sock = None
        self.secure = secure
        #self.window.mainloop()
        #print(dir(self))

    def _login(self):
        time.sleep(0.7)
        self._all_btns('disabled')
        try:
            self.name = simpledialog.askstring('Login','What is your name?', parent=self.window)
        except:
            pass
        finally:
            self._all_btns('normal')
        self.window.title(f'PyChat[{self.name}]')
        self.window.update()

    def _all_btns(self, State:str):
        self.startbtn.configure(state=State)
        self.stopbtn.configure(state=State)
        self.sendbtn.configure(state=State)

    def start(self):
        if self.name == None:
            Thread(target=self._login).start()
        #Thread(target=self._incoming).start()
        self.window.mainloop()

    def connect(self):
        self.sock = socket.socket()
        if self.secure:
            if not ssl.os.path.exists('certs/cert.pem'):
                print("Mising certificate")
                ssl.sys.exit(1)
            context = ssl.create_default_context(cafile='certs/cert.pem')
            self.sock = context.wrap_socket(self.sock, server_hostname=self.address)
        try:
            self.sock.connect((self.address, self.port))
            self._button_swap(self.stopbtn, self.startbtn)
            if self._encrypted:
                msg = b''
                while len(msg) < self._aes_pack_len:
                    msg += self.sock.recv(self._aes_pack_len)
                self._key = msg.strip(self._aes_buffer)
            self._running = True
            Thread(target=self._incoming).start()
        except Exception as e:
            self._button_swap(self.startbtn, self.stopbtn)
            self._running = False
            print(e)

    def disconnect(self):
        try:
            self.sock.send(self._STOP)
            self.sock.close()
            self._button_swap(self.startbtn, self.stopbtn)
            self._running = False
        except:
            self._running = True
            self._button_swap(self.stopbtn, self.startbtn)

    def _button_swap(self, onbtn:tkinter.Button, offbtn:tkinter.Button):
        onbtn.configure(state='normal')
        offbtn.configure(state='disabled')

    def send(self):
        text = f"{self.name} : " + self.textbox.get(1.0, tkinter.END)[:-1]
        self.textbox.delete(1.0, tkinter.END)
        self.text_insert(text + '\n')
        text = text.encode()
        pad = len(text) % 16
        if pad != 0:
            text += b'\x00' * (16 - pad)
        if self._encrypted:
            iv = Random.new().read(AES.block_size)
            text = iv + self._SEP + AES.new(self._key, AES.MODE_CBC, iv).encrypt(text)
        text += self._EOF
        for chunk in self._chunker(text):
            self.sock.send(chunk)

    def _chunker(self, msg: bytes):
        for pos in range(0,len(msg), 4096):
            yield msg[pos : pos + 4096]

    def _incoming(self):
        while not self._running:
            time.sleep(0.25)
        while self._running:
            if self._running and select.select([self.sock],[],[],2.0)[0]:
                msg = self.sock.recv(4096)
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
                    self._running =  not self._running
                    self.disconnect()
                    AlertBox(self.window, "Server is shutting down", ['OK'])
                    break
                self.text_insert(msg.decode() + end)

    def text_insert(self, text:str):
        self.messages.configure(state='normal')
        self.messages.insert(tkinter.END, text)
        self.messages.see(tkinter.END)
        self.messages.configure(state='disabled')

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self._running:
            self._running = False
            self.sock.sendall(self._STOP * 4)
            self.sock.close()

class AlertBox(simpledialog.SimpleDialog):
    def _set_transient(self, master, relx=10, rely=10):
        super()._set_transient(master, relx, rely)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A GUI python chat client")
    parser.add_argument('-i', '--address', type=str, required=True, default="pythonchatroom.com",
                        help='Chat Server Hostname or IP Address')
    parser.add_argument('-p', '--port', required=True, type=int, default=300,
                        help='Chat Server port number')
    parser.add_argument('-l', '--login', dest='name',
                        default=None, help='Chat Server Credentials')
    parser.add_argument('-s', dest="secure", action="store_true", help="Turn on ssl")
    args = parser.parse_args()
    with ChatWindow(**vars(args)) as chatclient:
        chatclient.start()