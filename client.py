import socket                #socket are imported for network communication.
import threading             # threading modules are imported for concurrent execution.
from tkinter import *         #tkinker is imported for creating the GUI
from tkinter import messagebox, ttk

username = input("Enter your username: ")
shift_value = 3                 # number 3 is used for Caesar Cipher encryption/decryption.

def encrypt_text(plain_text, shift):
    encrypted = ""                     #encrypt_text shifts each character of the input text forward by the shift value
    for char in plain_text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) + shift - shift_base) % 26 + shift_base)    #encryption formula 
        else:
            encrypted += char
    return encrypted

def decrypt_text(cipher_text, shift):
    decrypted = ""
    for char in cipher_text:              #decrypt_text shifts each character of the input text backward by the shift value
        if char.isalpha():   
            shift_base = 65 if char.isupper() else 97
            decrypted += chr((ord(char) - shift - shift_base) % 26 + shift_base)   #decryption formula 
        else:
            decrypted += char
    return decrypted

def connect_to_server():
    ip_address = ip_entry.get()
    port_number = int(port_entry.get())
    
    global client_socket
    client_socket = socket.socket()                #connect_to_server function attempts to connect to the server using the provided IP address and port number.
    try:
        client_socket.connect((ip_address, port_number))
        setup_window.destroy()
        setup_window.quit()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")
        error_message.config(text=f"Error: {e}")

def send_message():
    if message_entry.get().strip() != "":
        message_content = message_entry.get()
        encrypted_message = encrypt_text(message_content, shift_value)
        client_socket.send(encrypted_message.encode())                       #send_message function sends the message entered by the user.
        chat_listbox.insert(END, "You: " + message_content)
        encryption_listbox.insert(END, f"Original: {message_content}")
        encryption_listbox.insert(END, f"Encrypted: {encrypted_message}")
        message_entry.delete(0, END)

def receive_messages():
    while True:
        try:                                                      #receive_messages function runs in a loop to receive messages from the server.
            encrypted_message = client_socket.recv(1024).decode()
            decrypted_message = decrypt_text(encrypted_message, shift_value)
            chat_listbox.insert(END, server_username + ": " + decrypted_message)
            encryption_listbox.insert(END, f"Encrypted: {encrypted_message}")
            encryption_listbox.insert(END, f"Decrypted: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("Reception Error", f"Error receiving message: {e}")
            break

# Client GUI setup
setup_window = Tk()
setup_window.title("Client Setup")        #This section sets up the initial window for the client to input the server IP and port.
setup_window.geometry("500x500")
setup_window.resizable(False, False)
setup_window.configure(bg='#1e1e1e')

Label(setup_window, text="Enter Server IP:", bg='#1e1e1e', fg='#ffffff').pack(fill=X, padx=10, pady=5)
ip_entry = Entry(setup_window, bg='#3a3a3a', fg='#ffffff')
ip_entry.pack(fill=X, padx=10, pady=5)
ip_entry.insert(0, "192.168.218.219") #IP of the other device 

Label(setup_window, text="Enter Server Port:", bg='#1e1e1e', fg='#ffffff').pack(fill=X, padx=10, pady=5)
port_entry = Entry(setup_window, bg='#3a3a3a', fg='#ffffff')
port_entry.pack(fill=X, padx=10, pady=5)
port_entry.insert(0, "12345")

Button(setup_window, text="Connect to Server", command=connect_to_server, bg='#4caf50', fg="black").pack(padx=10, pady=20)

error_message = Label(setup_window, text="", fg="red", bg='#1e1e1e')
error_message.pack(fill=X, padx=10, pady=5)

setup_window.mainloop()

client_socket.send(username.encode())               # The client sends the username to the server and receives the server's username.
server_username = client_socket.recv(1024).decode()

main_window = Tk()
main_window.title(f"Client - {username}")
main_window.geometry("700x600")
main_window.configure(bg='#1e1e1e')

notebook = ttk.Notebook(main_window)
notebook.pack(fill=BOTH, expand=True)

chat_frame = Frame(notebook, bg='#1e1e1e')
notebook.add(chat_frame, text="Chat")

encryption_frame = Frame(notebook, bg='#1e1e1e')
notebook.add(encryption_frame, text="Encryption/Decryption")

style = ttk.Style()
style.configure('TNotebook.Tab', background='#3a3a3a', foreground='white')
style.map('TNotebook.Tab', background=[('selected', '#4caf50')])

chat_scrollbar = Scrollbar(chat_frame)     #Listbox and Scrollbar widgets are set up for displaying chat messages and encryption details.
chat_scrollbar.pack(side=RIGHT, fill=Y)
chat_listbox = Listbox(chat_frame, yscrollcommand=chat_scrollbar.set, bg='#3a3a3a', fg='#ffffff', selectbackground='#4caf50')
chat_listbox.pack(fill=BOTH, expand=True)
chat_scrollbar.config(command=chat_listbox.yview)

encryption_scrollbar = Scrollbar(encryption_frame)
encryption_scrollbar.pack(side=RIGHT, fill=Y)
encryption_listbox = Listbox(encryption_frame, yscrollcommand=encryption_scrollbar.set, bg='#3a3a3a', fg='#ffffff', selectbackground='#4caf50')
encryption_listbox.pack(fill=BOTH, expand=True)
encryption_scrollbar.config(command=encryption_listbox.yview)

bottom_frame = Frame(chat_frame, bg='#1e1e1e')
bottom_frame.pack(fill=X, side=BOTTOM)

message_entry = Entry(bottom_frame, bg='#3a3a3a', fg='#ffffff')
message_entry.pack(fill=X, side=LEFT, expand=True, padx=15, pady=15)  

send_button = Button(bottom_frame, text="Send Message", command=send_message, bg='#4caf50', fg="black")
send_button.pack(side=RIGHT, padx=5, pady=5)

threading.Thread(target=receive_messages).start()    # A thread is started to run the receive_messages function concurrently.
main_window.mainloop()             #  main_window.mainloop() starts the Tkinter event loop for the main window.

