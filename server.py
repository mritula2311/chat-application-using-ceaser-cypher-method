import socket
import threading
from tkinter import *
from tkinter import messagebox, ttk

username = input("Enter your username: ")
shift_value = 3

def encrypt_text(plain_text, shift):
    encrypted = ""
    for char in plain_text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) + shift - shift_base) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def decrypt_text(cipher_text, shift):
    decrypted = ""
    for char in cipher_text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            decrypted += chr((ord(char) - shift - shift_base) % 26 + shift_base)
        else:
            decrypted += char
    return decrypted

def setup_server():
    ip_address = ip_entry.get()
    port_number = int(port_entry.get())
    
    global server_socket
    server_socket = socket.socket()
    try:
        server_socket.bind((ip_address, port_number))
        server_socket.listen()
        global client_conn
        client_conn, client_addr = server_socket.accept()
        setup_window.destroy()
        setup_window.quit()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to bind or accept connection: {e}")
        error_message.config(text=f"Error: {e}")

def send_message():
    if message_entry.get().strip() != "":
        message_content = message_entry.get()
        encrypted_message = encrypt_text(message_content, shift_value)
        client_conn.send(encrypted_message.encode())
        chat_listbox.insert(END, "You: " + message_content)
        encryption_listbox.insert(END, f"Original: {message_content}")
        encryption_listbox.insert(END, f"Encrypted: {encrypted_message}")
        message_entry.delete(0, END)

def receive_messages():
    while True:
        try:
            encrypted_message = client_conn.recv(1024).decode()
            decrypted_message = decrypt_text(encrypted_message, shift_value)
            chat_listbox.insert(END, client_username + ": " + decrypted_message)
            encryption_listbox.insert(END, f"Encrypted: {encrypted_message}")
            encryption_listbox.insert(END, f"Decrypted: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("Reception Error", f"Error receiving message: {e}")
            break

# Server GUI setup
setup_window = Tk()
setup_window.title("Server Setup")
setup_window.geometry("400x300")
setup_window.resizable(False, False)
setup_window.configure(bg='#1e1e1e')

Label(setup_window, text="Enter IP:", bg='#1e1e1e', fg='#ffffff').pack(fill=X, padx=10, pady=5)
ip_entry = Entry(setup_window, bg='#3a3a3a', fg='#ffffff')
ip_entry.pack(fill=X, padx=10, pady=5)
ip_entry.insert(0, "192.168.218.219")

Label(setup_window, text="Enter Port:", bg='#1e1e1e', fg='#ffffff').pack(fill=X, padx=10, pady=5)
port_entry = Entry(setup_window, bg='#3a3a3a', fg='#ffffff')
port_entry.pack(fill=X, padx=10, pady=5)
port_entry.insert(0, "12345")

Button(setup_window, text="Set IP", command=setup_server, bg='#4caf50', fg="white").pack(padx=10, pady=20)

error_message = Label(setup_window, text="", fg="red", bg='#1e1e1e')
error_message.pack(fill=X, padx=10, pady=5)

setup_window.mainloop()

client_conn.send(username.encode())
client_username = client_conn.recv(1024).decode()

main_window = Tk()
main_window.title(f"Server - {username}")
main_window.geometry("600x500")
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

chat_scrollbar = Scrollbar(chat_frame)
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
message_entry.pack(fill=X, side=LEFT, expand=True, padx=5, pady=5)

send_button = Button(bottom_frame, text="Send Message", command=send_message, bg='#4caf50', fg="white")
send_button.pack(side=RIGHT, padx=5, pady=5)

threading.Thread(target=receive_messages).start()
main_window.mainloop()
