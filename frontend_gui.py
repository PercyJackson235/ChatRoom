#!/usr/bin/python3
import tkinter
from tkinter import scrolledtext
from tkinter import simpledialog
import time
import socket
from threading import Thread
import select

class ChatWindow(object):
    def __init__(self):
        self.window = tkinter.Tk()
        self.window.attributes('-zoomed', True)
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
        self.messages.insert(tkinter.END, 'hello')
        self.messages.pack(expand=True, fill=tkinter.BOTH, side=tkinter.BOTTOM, pady=(5,2), padx=10)
        self.messages.configure(state="disabled")
        middleframe.pack(expand=True, fill=tkinter.BOTH)
        bottomframe = tkinter.Frame(self.window)
        self.textbox = tkinter.Text(bottomframe)
        self.textbox.pack(expand=True, fill=tkinter.BOTH, side=tkinter.LEFT, pady=(0,5), padx=10)
        self.sendbtn = tkinter.Button(bottomframe, text='Send', command=self.send)
        self.sendbtn.pack(side=tkinter.RIGHT)
        bottomframe.pack(expand=True, fill=tkinter.BOTH)
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
            Thread(target=self._login).start()
        self.window.mainloop()

    def connect(self):
            try:
                self._button_swap(self.stopbtn, self.startbtn)
            except:
                self._button_swap(self.startbtn, self.stopbtn)

    def disconnect(self):
        try:
            self._button_swap(self.startbtn, self.stopbtn)
        except:
            self._button_swap(self.stopbtn, self.startbtn)

    def _button_swap(self, onbtn:tkinter.Button, offbtn:tkinter.Button):
        onbtn.configure(state='normal')
        offbtn.configure(state='disabled')

    def send(self):
        text = f"{self.name}: " + self.textbox.get(1.0, tkinter.END)[:-1]
        print(text, end='')
        print('\nAbove is "self.text.get(1.0, tkinter.END)[:-1]"')
        self.textbox.delete(1.0, tkinter.END)
        self.text_insert(text)

    def text_insert(self, text:str):
        self.messages.configure(state='normal')
        self.messages.insert(tkinter.END, text + '\n')
        self.messages.configure(state='disabled')

if __name__ == "__main__":
    chatroom = ChatWindow()
    chatroom.start()