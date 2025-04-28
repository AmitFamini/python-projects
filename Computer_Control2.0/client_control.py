import socket
import threading
import time
import cv2
import numpy as np
import pyautogui
import tkinter as tk
from pynput.mouse import Button, Controller as MouseController
from pynput.keyboard import Key, Controller as KeyboardController
from AES_utils import decrypt_data


class ScreenClient:
    def __init__(self, server_ip, screen_port, parent):
        self.server_ip = server_ip
        self.screen_port = screen_port
        self.buffer_size = 65507  # Max UDP packet size
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.settimeout(2)
        self.parent = parent  # reference to the ScreenSharingClient

    def capture_screen_with_cursor(self):
        try:
            screenshot = pyautogui.screenshot()
            screenshot = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)
            cursor_x, cursor_y = pyautogui.position()
            cv2.circle(screenshot, (cursor_x, cursor_y), 5, (0, 0, 255), -1)
            return screenshot
        except Exception as e:
            print(f"Error capturing screen: {e}")
            return None

    def send_screen_to_server(self):
        while self.parent.running:
            if not self.parent.enable_screen:
                time.sleep(0.1)
                continue

            frame = self.capture_screen_with_cursor()
            if frame is None:
                continue

            try:
                _, frame_encoded = cv2.imencode('.jpg', frame)
                frame_bytes = frame_encoded.tobytes()
                frame_size = len(frame_bytes)
                self.udp_socket.sendto(frame_size.to_bytes(4, byteorder='big'), (self.server_ip, self.screen_port))

                for i in range(0, frame_size, self.buffer_size):
                    self.udp_socket.sendto(frame_bytes[i:i + self.buffer_size], (self.server_ip, self.screen_port))

                time.sleep(1 / 40)  # Target ~40 FPS
            except Exception as e:
                print(f"Error sending screen data: {e}")


class ControlClient:
    def __init__(self, server_ip, control_port, parent):
        self.server_ip = server_ip
        self.control_port = control_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mouse = MouseController()
        self.keyboard = KeyboardController()
        self.parent = parent  # reference to ScreenSharingClient

    def connect(self):
        try:
            self.socket.connect((self.server_ip, self.control_port))
            print("Connected to control server")
        except Exception as e:
            print(f"Error connecting to control server: {e}")
            exit(1)

    def handle_mouse_action(self, action, *args):
        if not self.parent.enable_mouse:
            return
        try:
            if action == "Pointer moved":
                x, y = args
                # adjust for window borders if needed
                self.mouse.position = (x - 8, y - 31)
            elif action == "Pressed":
                self.mouse.press(Button.left)
            elif action == "Released":
                self.mouse.release(Button.left)
            elif action == "Right Pressed":
                self.mouse.press(Button.right)
            elif action == "Right Released":
                self.mouse.release(Button.right)
            elif action == "Scrolled up":
                self.mouse.scroll(0, 1)
            elif action == "Scrolled down":
                self.mouse.scroll(0, -1)
        except Exception as e:
            print(f"Error handling mouse action: {e}")

    def handle_keyboard_action(self, action, key):
        if not self.parent.enable_keyboard:
            return
        try:
            if action == "Alphanumeric key pressed":
                self.keyboard.press(key)
                self.keyboard.release(key)
            elif action == "Special key pressed":
                key = eval(key)
                self.keyboard.press(key)
                self.keyboard.release(key)
            elif action.endswith("released"):
                key = eval(key)
                self.keyboard.release(key)
        except Exception as e:
            print(f"Error handling keyboard action: {e}")

    def process_message(self, msg):
        print(f"Received message: {msg}")
        try:
            if msg.startswith("Pointer moved to"):
                # Expected format: "Pointer moved to (x, y)"
                cords = msg.split("to")[1].strip().strip("()")
                x, y = map(int, cords.split(","))
                self.handle_mouse_action("Pointer moved", x, y)
            elif msg.startswith("Pressed at") or msg.startswith("Released at"):
                action = "Pressed" if "Pressed" in msg else "Released"
                self.handle_mouse_action(action)
            elif msg.startswith("Right Pressed at") or msg.startswith("Right Released at"):
                action = "Right Pressed" if "Right Pressed" in msg else "Right Released"
                self.handle_mouse_action(action)
            elif msg.startswith("Scrolled"):
                direction = "Scrolled down" if "down" in msg else "Scrolled up"
                self.handle_mouse_action(direction)
            elif "key" in msg:
                # Expected format: "<action> <key>"
                action, key = msg.rsplit(" ", 1)
                self.handle_keyboard_action(action, key)
        except Exception as e:
            print(f"Error processing message: {msg} | Exception: {e}")

    def listen_to_server(self):
        while self.parent.running:
            try:
                msg_length = self.socket.recv(2).decode()
                if not msg_length.isnumeric():
                    continue
                encrypted_msg = self.socket.recv(int(msg_length)).decode()
                msg = decrypt_data(encrypted_msg)
                self.process_message(msg)
            except Exception as e:
                print(f"Error receiving message: {e}")
                break  # Exit on error (e.g. disconnect)


class ScreenSharingClient:
    def __init__(self):
        self.server_ip = None
        self.running = True
        self.enable_mouse = True
        self.enable_keyboard = True
        self.enable_screen = True
        self.screen_client = None
        self.control_client = None

    def launch_gui(self):
        """Create the client GUI for entering the server IP and toggling controls."""
        self.root = tk.Tk()
        self.root.title("Client Screen Sharing")

        # Server IP entry
        tk.Label(self.root, text="Server IP:").pack(pady=5)
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.pack(pady=5)
        tk.Button(self.root, text="Connect", command=self.connect_to_server).pack(pady=5)

        # Toggles for controls (active after connecting)
        self.mouse_var = tk.BooleanVar(value=True)
        self.keyboard_var = tk.BooleanVar(value=True)
        self.screen_var = tk.BooleanVar(value=True)

        self.toggle_frame = tk.Frame(self.root)
        tk.Checkbutton(self.toggle_frame, text="Enable Mouse Control", variable=self.mouse_var,
                       command=self.toggle_mouse).pack(pady=2)
        tk.Checkbutton(self.toggle_frame, text="Enable Keyboard Control", variable=self.keyboard_var,
                       command=self.toggle_keyboard).pack(pady=2)
        tk.Checkbutton(self.toggle_frame, text="Enable Screen Sharing", variable=self.screen_var,
                       command=self.toggle_screen).pack(pady=2)
        self.toggle_frame.pack(pady=10)

        # Disconnect button
        tk.Button(self.root, text="Disconnect", command=self.disconnect).pack(pady=5)
        self.root.protocol("WM_DELETE_WINDOW", self.disconnect)
        self.root.mainloop()

    def connect_to_server(self):
        self.server_ip = self.ip_entry.get().strip()
        if not self.server_ip:
            print("Please enter a valid server IP.")
            return
        # Initialize screen and control clients, passing self for flag checking.
        self.screen_client = ScreenClient(self.server_ip, 8080, self)
        self.control_client = ControlClient(self.server_ip, 8820, self)
        self.control_client.connect()

        # Start threads for sending screen data and receiving control messages.
        self.screen_thread = threading.Thread(target=self.screen_client.send_screen_to_server, daemon=True)
        self.control_thread = threading.Thread(target=self.control_client.listen_to_server, daemon=True)
        self.screen_thread.start()
        self.control_thread.start()

    def toggle_mouse(self):
        self.enable_mouse = self.mouse_var.get()
        print(f"Mouse control {'enabled' if self.enable_mouse else 'disabled'}.")

    def toggle_keyboard(self):
        self.enable_keyboard = self.keyboard_var.get()
        print(f"Keyboard control {'enabled' if self.enable_keyboard else 'disabled'}.")

    def toggle_screen(self):
        self.enable_screen = self.screen_var.get()
        print(f"Screen sharing {'enabled' if self.enable_screen else 'disabled'}.")

    def disconnect(self):
        print("Disconnecting...")
        self.running = False
        try:
            if self.control_client:
                self.control_client.socket.close()
        except Exception as e:
            print(f"Error disconnecting: {e}")
        self.root.destroy()

    def start(self):
        self.launch_gui()


if __name__ == "__main__":
    client = ScreenSharingClient()
    client.start()
