import socket
from threading import Thread
import tkinter as tk
from tkinter import filedialog, messagebox
from pyDH import DiffieHellman
from os.path import basename, getsize
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

PACKETS_PER_PRINTS = 10
BUFFER_SIZE = 1024 * 1024  # 1 Mb
BUFFER_PAYLOAD_SIZE = 1024 * 1000  # < 1 Mb
LOCAL_HOST = "127.0.0.1"
TIMEOUT = 5

joinerServer = []  # Server thread list (to join)
senderRunning = True
index = 0


class DataPacket:
    def __init__(self, file_name, size, packet_index, data, start_size):
        self.file_name = file_name
        self.size = size
        self.packet_index = packet_index
        self.data = data
        self.start_size = start_size
        self.iv = secrets.token_bytes(16)


class GUIApp:
    def __init__(self, root):
        self.files = []
        self.t = Thread()
        self.root = root
        self.root.title("File Transfer")

        self.port_text = tk.StringVar()
        self.port_text.set("")

        # Port Label
        self.port_label = tk.Label(root, text="Port:")
        self.port_label.grid(row=0, column=0, padx=(
            10, 0), pady=10, sticky="w")

        # Port Entry (Number Field)
        self.port = tk.Entry(root, width=20)
        self.port.grid(row=0, column=0, padx=50, pady=10,
                       sticky="ew", columnspan=3)
        self.port.bind("<Return>", self.onEnterPressed)

        # Multiple File Selector
        self.file_selector_button = tk.Button(
            root, text="Select Files", command=self.selectFiles)
        self.file_selector_button.grid(
            row=0, column=2, columnspan=2, padx=10, pady=10)

        # Send Button
        self.send_button = tk.Button(root, text="Send", command=self.sendFiles)
        self.send_button.grid(row=1, column=0, columnspan=2, pady=10)
        self.send_button.bind("<Return>", self.onEnterPressed)

        # Client Label
        self.client_label = tk.Label(root, text="Client: ")
        self.client_label.grid(
            row=2, column=0, padx=(10, 0), pady=10, sticky="w")

        # Server Label
        self.server_label = tk.Label(root, text="Server: ")
        self.server_label.grid(
            row=0, column=4, padx=(10, 0), pady=10, sticky="w")

        # Server Port Label
        self.server_port_label = tk.Label(root, textvariable=self.port_text)
        self.server_port_label.grid(
            row=0, column=4, padx=(50, 0), pady=10, sticky="w")

        # Server Area
        self.server_area = tk.Text(root, state=tk.DISABLED)
        self.server_area.grid(row=1, rowspan=3, column=4,
                              columnspan=4, padx=10, pady=10, sticky="ewns")

        # Client Area
        self.client_area = tk.Text(root, state=tk.DISABLED)
        self.client_area.grid(row=3, column=0, columnspan=4,
                              padx=10, pady=10, sticky="ewns")

        root.columnconfigure(4, weight=1)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(3, weight=1)

    def onEnterPressed(self, event):
        if event.widget == self.port or event.widget == self.send_button:
            self.sendFiles()

    def selectFiles(self):
        f = filedialog.askopenfilenames()
        self.files = list(f)

        print(f, self.files)

        self.client_area.config(state=tk.NORMAL)
        self.client_area.delete(1.0, tk.END)

        for file in self.files:
            self.client_area.insert(tk.END, "Selected: " + file + '\n')

        self.client_area.config(state=tk.DISABLED)

    def setServerPort(self, port):
        self.port_text.set("(port: " + str(port) + ")")
        self.port.insert(tk.END, str(port))

    def appendToClientField(self, message):
        current_content = self.client_area.get("1.0", tk.END)

        if current_content and current_content != "\n":
            new_content = f"{current_content}{message}"
        else:
            new_content = message

        self.client_area.config(state=tk.NORMAL)
        self.client_area.delete("1.0", tk.END)
        self.client_area.insert("1.0", new_content)
        self.client_area.config(state=tk.DISABLED)
        self.client_area.see("end")
        self.client_area.update_idletasks()

    def appendToServerField(self, message):
        current_content = self.server_area.get("1.0", tk.END)

        if current_content and current_content != "\n":
            new_content = f"{current_content}{message}"
        else:
            new_content = message

        self.server_area.config(state=tk.NORMAL)
        self.server_area.delete("1.0", tk.END)
        self.server_area.insert("1.0", new_content)
        self.server_area.config(state=tk.DISABLED)
        self.server_area.see("end")
        self.server_area.update_idletasks()

    def sendFiles(self):
        global senderRunning
        port = self.port.get()

        self.port.config(state=tk.DISABLED)
        self.file_selector_button.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED)

        try:
            if self.files == []:
                raise ValueError
            port = int(port)

            print(f"Sending files to port {port}...")

            senderRunning = True
            self.t = Thread(target=messageSender, args=(port, self.files))
            self.t.start()

            self.root.after(100, self.checkSenderStatus)

        except ValueError:
            print("Please enter a valid port number.")
            self.port.config(state=tk.NORMAL)
            self.file_selector_button.config(state=tk.NORMAL)
            self.send_button.config(state=tk.NORMAL)

    def checkSenderStatus(self):
        if self.t.is_alive():
            # If the sender thread is still running, schedule another check after 100 milliseconds
            self.root.after(100, self.checkSenderStatus)
        else:
            self.t.join()
            self.port.config(state=tk.NORMAL)
            self.file_selector_button.config(state=tk.NORMAL)
            self.send_button.config(state=tk.NORMAL)

# Key Derivation Function (KDF) adding salt :/


def derive_key(secret):
    salt = b"thisis somesalt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Adjust based on your security requirements
        salt=salt,
        length=32  # AES-256 key size
    )
    return kdf.derive(secret.encode('utf-8'))


def encrypt(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext


def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    return message


def errorHandler(e, message=""):
    if message == "":
        messagebox.showerror("Error", f"{e}")
    else:
        messagebox.showerror("Error", f"{message}\n({e})")


def startServer():
    try:
        threads = []
        run = True

        s = socket.socket()
        s.bind((LOCAL_HOST, 0))  # 0 - automatically assign a port
        s.listen(TIMEOUT)

        app.setServerPort(s.getsockname()[1])

        app.appendToServerField(f"Server started on port {s.getsockname()[1]}")

        while run:
            t = Thread(target=reciver, args=(s.accept()))
            t.start()
            threads.append(t)

            if (len(joinerServer) != 0):
                print("Joining thread",  joinerServer[0])
                threads[joinerServer[0]].join()
                threads[joinerServer[0]] == ""

        s.close()
    except Exception as e:
        print(e)


def reciver(client_socket, client_address):
    global index
    i = index
    index += 1
    run = True

    dh = DiffieHellman()

    publicKey = dh.gen_public_key()

    publicKey = str(publicKey).encode("utf-8")

    client_socket.send(publicKey)
    publicKeyC = int(client_socket.recv(2048).decode("utf-8"))

    sharedKey = dh.gen_shared_key(publicKeyC)

    aesKey = derive_key(sharedKey)

    iv = str(sharedKey)[:16].encode("utf-8")

    while run:
        try:
            message = client_socket.recv(BUFFER_SIZE)
            message = pickle.loads(decrypt(message, aesKey, iv))
            iv = message.iv
            with open("Prejeto/"+message.file_name, "ab") as f:
                f.write(message.data)
                f.close()
            if message.start_size == message.size:
                app.appendToServerField(f"Recived: {message.file_name} from {
                                        client_address} | 100%")
            elif message.packet_index % PACKETS_PER_PRINTS == 0:
                app.appendToServerField(f"Reciving: {message.file_name} from {client_address} | {
                                        int((message.start_size / message.size) * 100)}%")

            client_socket.send("1".encode("utf-8"))

        except ConnectionResetError:
            print("Connection forcibly closed.")
            client_socket.close()
            joinerServer.append(i)
            run = False

        except Exception as e:
            print(e)
            client_socket.close()
            joinerServer.append(i)
            run = False


def messageSender(port, files):
    global senderRunning
    try:
        s = socket.socket()

        try:
            s.connect((LOCAL_HOST, port))
        except ConnectionRefusedError as e:
            errorHandler(e, "Server not available")
            return

        s.settimeout(1)

        dh = DiffieHellman()

        publicKey = dh.gen_public_key()
        publicKey = str(publicKey).encode("utf-8")
        s.send(publicKey)
        publicKeyS = int(s.recv(2048).decode("utf-8"))

        sharedKey = dh.gen_shared_key(publicKeyS)

        aesKey = derive_key(sharedKey)
        iv = str(sharedKey)[:16].encode("utf-8")

        while senderRunning:
            try:
                for file in files:
                    print("Sending file: " + file)
                    with open(file, "rb") as f:
                        index = 0
                        while True:
                            data = f.read(BUFFER_PAYLOAD_SIZE)
                            packet = DataPacket(basename(file), getsize(
                                file), index, data, f.tell())
                            try:
                                encripted_packet = encrypt(
                                    pickle.dumps(packet), aesKey, iv)
                                iv = packet.iv
                                s.send(encripted_packet)
                                s.recv(1024)
                            except socket.timeout as e:
                                print(e)
                                s.send(packet)

                            if f.tell() == getsize(file):
                                f.close()
                                app.appendToClientField(f"Sent: {file} | 100%")
                                break
                            if index % PACKETS_PER_PRINTS == 0:
                                app.appendToClientField(f"Sending: {file} | {
                                                        int((f.tell() / getsize(file)) * 100)}%")
                            index += 1
                files = []
                senderRunning = False
            except ConnectionResetError as e:
                errorHandler(e, "Server crashed")
            except Exception as e:
                errorHandler(e)

        if not senderRunning:
            s.close()
    except Exception as e:
        errorHandler(e)


if __name__ == "__main__":
    root = tk.Tk()
    app = GUIApp(root)
    tS = Thread(target=startServer)
    tS.start()
    root.mainloop()
    tS.join()
