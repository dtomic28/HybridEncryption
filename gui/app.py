import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from backend.file_transfer import FileTransfer  # noqa


class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Transfer")
        self.handler = None  # FileTransfer handler instance
        self.setup_gui()

    def setup_gui(self):
        # Default values for IP and Port
        default_ip = "127.0.0.1"
        default_port = "12345"

        # IP and Port fields
        tk.Label(self.root, text="IP Address:").pack()
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.insert(0, default_ip)  # Set default IP
        self.ip_entry.pack()

        tk.Label(self.root, text="Port:").pack()
        self.port_entry = tk.Entry(self.root)
        self.port_entry.insert(0, default_port)  # Set default Port
        self.port_entry.pack()

        # Server and Client buttons
        tk.Button(self.root, text="Start Server",
                  command=self.start_server).pack(pady=5)
        tk.Button(self.root, text="Start Client",
                  command=self.start_client).pack(pady=5)

        # Send File button (initially disabled)
        self.file_button = tk.Button(
            self.root, text="Send File", command=self.send_file, state=tk.DISABLED)
        self.file_button.pack(pady=5)

    def start_server(self):
        """Starts the server."""
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        self.handler = FileTransfer(is_server=True, ip=ip, port=port)
        self.handler.start()
        # Enable the Send File button for testing
        self._update_gui_state(True)
        self._show_info("Server started. Waiting for connection...")

    def start_client(self):
        """Starts the client."""
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        self.handler = FileTransfer(is_server=False, ip=ip, port=port)
        self.handler.start()
        self._update_gui_state(True)
        self._show_info("Client started. Connecting...")

    def send_file(self):
        """Triggers file selection and starts sending the file."""
        if not self.handler:
            self._show_error("You must start as a Server or Client first.")
            return

        # Open file selection dialog
        file_path = filedialog.askopenfilename()
        if not file_path:
            self._show_info("No file selected.")
            return

        # Start file sending in a new thread
        def send_with_error_handling():
            try:
                # Wait for handshake to complete
                if not self.handler.wait_for_handshake():
                    self._show_error("Handshake not completed")
                    return

                # Send file
                self.handler.send_file(file_path)
                self._show_info("File sent successfully")
            except Exception as e:
                self._show_error(str(e))

        threading.Thread(target=send_with_error_handling).start()

    def _show_info(self, message):
        """Show information message on the main thread."""
        self.root.after(0, messagebox.showinfo, "Info", message)

    def _show_error(self, message):
        """Show error message on the main thread."""
        self.root.after(0, messagebox.showerror, "Error", message)

    def _update_gui_state(self, enable):
        """Enable or disable the 'Send File' button on the main thread."""
        self.root.after(0, self.file_button.config, {
                        'state': tk.NORMAL if enable else tk.DISABLED})


if __name__ == "__main__":
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()
