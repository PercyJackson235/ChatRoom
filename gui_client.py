#!/usr/bin/python3
import tkinter
from tkinter import scrolledtext
from tkinter import simpledialog
import time
import socket
from threading import Thread
import select
from Crypto.Cipher import AES

class ChatWindow(object):
    def __init__(self, address:str = None, port:int = 300, name:str = None):
        self.address = address
        self.port = int(port)
        self.name = name
        self._EOF = b'\x90' * 3 + b'\x03'
        self._STOP = b'\x90' * 3 + b'\x04'
        self._running = False
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
        self.cihperobj = AES.new('PercyJackson235!')
        #self.window.mainloop()
        #print(dir(self))

    def _login(self):
        time.sleep(0.5)
        self._all_btns('disabled')
        try:
            self.name = simpledialog.askstring('Login','What is your name?', parent=self.window)
        except:
            self.name = 'guest'
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
            Thread(target=self._login)
        Thread(target=self._incoming).start()
        self.window.mainloop()

    def connect(self):
        self.sock = socket.socket()
        try:
            self.sock.connect((self.address, self.port))
            self._button_swap(self.stopbtn, self.startbtn)
            self._running = True
        except:
            self._button_swap(self.startbtn, self.stopbtn)
            self._running = False

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
        text = f"{self.name}: " + self.textbox.get(1.0, tkinter.END)[:-1]
        print(text, end='')
        print('\nAbove is "self.text.get(1.0, tkinter.END)[:-1]"')
        self.textbox.delete(1.0, tkinter.END)
        self.text_insert(text + '\n')
        text = text.encode() + self._EOF
        pad = len(text) % 16
        if pad != 0:
            text += b'\x00' * (16 - pad)
            print(len(text) % 16)
        for chunk in self._chunker(text):
            chunk = self.cihperobj.encrypt(chunk)
            print(len(chunk))
            print('Sent ',self.sock.send(chunk))

    def _chunker(self, msg: bytes):
        for pos in range(0,len(msg), 4096):
            yield msg[pos : pos + 4096]

    def _incoming(self):
        print('inside incoming loop')
        while not self._running:
            time.sleep(0.25)
        while self._running:
            print('inside run loop')
            if select.select([self.sock],[],[],2.0)[0] and self._running:
                print('inside select loop')
                msg = self.sock.recv(4096)
                print(len(msg))
                msg = self.cihperobj.decrypt(msg)
                msg = msg.rstrip(b'\x00')
                msg = msg.replace(self._EOF, b'\n').decode()
                self.text_insert(msg)

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

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="A GUI python chat client")
    parser.add_argument('-i', '--address', type=str, required=True,
                        help='Chat Server Hostname or IP Address')
    parser.add_argument('-p', '--port', required=True, type=int, help='Chat Server port number')
    parser.add_argument('-l', '--login', dest='name',
                        default=None, help='Chat Server Credentials')
    args = parser.parse_args()
    with ChatWindow(**vars(args)) as chatclient:
        chatclient.start()