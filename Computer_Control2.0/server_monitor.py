import socket
import threading
import cv2
import numpy as np
import tkinter as tk
from pynput import mouse, keyboard
from AES_utils import encrypt_data


class ControlServer:
    def __init__(self, ip="0.0.0.0", port=8820):
        self.ip = ip
        self.port = port
        self.control_socket = None
        self.client_address = None

    def start(self):
        try:
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.bind((self.ip, self.port))
            self.control_socket.listen(1)
            print("Control server is up and running")
            self.control_socket, self.client_address = self.control_socket.accept()
            print(f"Client {self.client_address} connected")
        except Exception as e:
            print(f"Error setting up control socket: {e}")
            exit(1)

    def send_control_message(self, msg):
        """Encrypt and send control message via TCP."""
        try:
            encrypted_msg = encrypt_data(msg)
            msg_length = str(len(encrypted_msg)).zfill(2)
            self.control_socket.send((msg_length + encrypted_msg).encode())
        except Exception as e:
            print(f"Error sending control message: {e}")


class ScreenServer:
    def __init__(self, ip="0.0.0.0", port=8080):
        self.ip = ip
        self.port = port
        self.buffer_size = 65507  # Max UDP packet size


class InputHandler:
    def __init__(self, control_server, app):
        self.control_server = control_server
        self.app = app  # reference to ScreenSharingApp for checking toggles

    def on_press(self, key):
        if not self.app.enable_keyboard:
            return
        msg = (f'Alphanumeric key pressed {key.char}' if hasattr(key, 'char')
               else f'Special key pressed {key}')
        self.control_server.send_control_message(msg)

    def on_release(self, key):
        if not self.app.enable_keyboard:
            return
        msg = f'released {key}'
        self.control_server.send_control_message(msg)

    def on_click(self, x, y, button, pressed):
        if not self.app.enable_mouse:
            return
        action = "Pressed" if pressed else "Released"
        if button == mouse.Button.left:
            msg = f'{action} at ({x}, {y})'
        else:
            msg = f'Right {action} at ({x}, {y})'
        self.control_server.send_control_message(msg)

    def on_move(self, x, y):
        if not self.app.enable_mouse:
            return
        msg = f'Pointer moved to ({x}, {y})'
        self.control_server.send_control_message(msg)

    def on_scroll(self, x, y, dx, dy):
        if not self.app.enable_mouse:
            return
        direction = 'down' if dy < 0 else 'up'
        msg = f'Scrolled {direction} at ({x}, {y})'
        self.control_server.send_control_message(msg)


class ScreenSharingApp:
    def __init__(self):
        # default toggles set to True
        self.enable_mouse = True
        self.enable_keyboard = True
        self.enable_screen = True
        self.running = True

        self.control_server = ControlServer()
        self.screen_server = ScreenServer()

    def run_screen_server(self):
        """Run the UDP screen server loop with toggle support."""
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.screen_server.ip, self.screen_server.port))
        print("Screen server is listening for UDP packets...")

        while self.running:
            try:
                udp_socket.settimeout(1.0)
                frame_size_bytes, client_address = udp_socket.recvfrom(4)
                frame_size = int.from_bytes(frame_size_bytes, byteorder='big')
                frame_data = b''
                while len(frame_data) < frame_size:
                    packet, _ = udp_socket.recvfrom(self.screen_server.buffer_size)
                    frame_data += packet
                frame_array = np.frombuffer(frame_data, dtype=np.uint8)
                frame = cv2.imdecode(frame_array, cv2.IMREAD_COLOR)

                # Only show screen if sharing is enabled.
                if frame is not None and self.enable_screen:
                    cv2.imshow('Screen Sharing', frame)
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        self.running = False
                        break
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving frame: {e}")

        udp_socket.close()
        cv2.destroyAllWindows()

    def launch_gui(self):
        """Create the server GUI for toggling controls and stopping connection."""
        self.root = tk.Tk()
        self.root.title("Server Control Panel")

        # Toggle for mouse control
        self.mouse_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.root, text="Enable Mouse Control", variable=self.mouse_var,
                       command=self.toggle_mouse).pack(pady=5)

        # Toggle for keyboard control
        self.keyboard_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.root, text="Enable Keyboard Control", variable=self.keyboard_var,
                       command=self.toggle_keyboard).pack(pady=5)

        # Toggle for screen sharing
        self.screen_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self.root, text="Enable Screen Sharing", variable=self.screen_var,
                       command=self.toggle_screen).pack(pady=5)

        # Button to stop connection
        tk.Button(self.root, text="Stop Connection", command=self.stop_connection).pack(pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.stop_connection)
        self.root.mainloop()

    def toggle_mouse(self):
        self.enable_mouse = self.mouse_var.get()
        print(f"Mouse control {'enabled' if self.enable_mouse else 'disabled'}.")

    def toggle_keyboard(self):
        self.enable_keyboard = self.keyboard_var.get()
        print(f"Keyboard control {'enabled' if self.enable_keyboard else 'disabled'}.")

    def toggle_screen(self):
        self.enable_screen = self.screen_var.get()
        print(f"Screen sharing {'enabled' if self.enable_screen else 'disabled'}.")

    def stop_connection(self):
        print("Stopping connection...")
        self.running = False
        try:
            self.control_server.control_socket.close()
        except Exception as e:
            print(f"Error closing control socket: {e}")
        # Stop the keyboard and mouse listeners.
        self.keyboard_listener.stop()
        self.mouse_listener.stop()
        self.root.destroy()

    def start(self):
        # Start control connection (blocking until a client connects)
        self.control_server.start()

        # Create the input handler with access to the toggle flags
        input_handler = InputHandler(self.control_server, self)

        # Create and start listeners for keyboard and mouse
        self.keyboard_listener = keyboard.Listener(
            on_press=input_handler.on_press,
            on_release=input_handler.on_release
        )
        self.mouse_listener = mouse.Listener(
            on_move=input_handler.on_move,
            on_click=input_handler.on_click,
            on_scroll=input_handler.on_scroll
        )
        self.keyboard_listener.start()
        self.mouse_listener.start()

        # Start the screen server thread (UDP receiving)
        screen_server_thread = threading.Thread(target=self.run_screen_server, daemon=True)
        screen_server_thread.start()

        # Launch the Tkinter GUI (this call is blocking until the window is closed)
        self.launch_gui()


if __name__ == "__main__":
    app = ScreenSharingApp()
    app.start()
